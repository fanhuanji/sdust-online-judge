# -*- coding: utf-8 -*-
from math import ceil
from datetime import datetime

from models import pg_models
from models import redis_models
from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker

from models import mysql_models

from conf import judger_id

MysqlSession = sessionmaker(bind=mysql_models.engine)
mysql_session = MysqlSession()

PgSession = sessionmaker(bind=pg_models.engine)
pg_session = PgSession()


def get_problem_title(problem_id, test_data_id):
    return 'sdustoj %s-%s' % (problem_id, test_data_id)


def update(**kwargs):
    pid = kwargs['pid']
    test_data = pg_session.query(pg_models.TestData).join(
        pg_models.ProblemTestData, pg_models.TestData.id == pg_models.ProblemTestData.test_data_id
    ).filter_by(
        problem_id=pid, deleted=False
    ).all()

    special_judge = pg_session.query(pg_models.SpecialJudge).filter_by(
        problem_id=pid, available=True, deleted=False).order_by(desc(pg_models.SpecialJudge.id)).first()

    limits = pg_session.query(pg_models.Limit).filter_by(problem_id=pid).all()
    time_limit = 0
    memory_limit = 0
    for limit in limits:
        if limit.time_limit > time_limit:
            time_limit = limit.time_limit
        if limit.memory_limit > memory_limit:
            memory_limit = limit.memory_limit

    problems = []
    for data in test_data:
        p_title = get_problem_title(pid, data.id)
        p = mysql_session.query(mysql_models.Problem).filter_by(title=p_title).first()
        if p is not None:
            p.time_limit = ceil(time_limit / 1000)
            p.memory_limit = ceil(memory_limit / 1000)
            p.spj = '0' if special_judge is None else '1'
            problems.append((p, data, special_judge))
        else:
            problem = mysql_models.Problem(
                title=p_title, description='Problem %s auto-generated by SDUSTOJ.' % (pid, ),
                input='', output='', sample_input='', sample_output='',
                spj='0' if special_judge is None else '1',
                hint='', source='SDUSTOJ',
                time_limit=ceil(time_limit / 1000), memory_limit=ceil(memory_limit / 1000)
            )
            mysql_session.add(problem)
            problems.append((problem, data, special_judge))

    mysql_session.commit()

    judge = pg_session.query(pg_models.Judge).filter_by(id=judger_id).first()
    judge.last_update = datetime.now()
    pg_session.commit()

    for (p, t, s) in problems:
        redis_models.TestData.write(p.problem_id, t.test_in, t.test_out)
        if s is not None:
            redis_models.SpecialJudge.write(p.problem_id, s.code)
        print('    Updated problem: ' + str(p.problem_id))


def update_meta(**kwargs):
    mid = kwargs['mid']
    problems = pg_session.query(pg_models.Problem).filter_by(deleted=False, meta_problem_id=mid).all()
    for problem in problems:
        update(pid=problem.id)


def update_all(**kwargs):
    if kwargs:
        kwargs.clear()
    meta_problems = pg_session.query(pg_models.MetaProblem).filter_by(deleted=False).all()
    for meta_problem in meta_problems:
        update_meta(mid=meta_problem.id)
