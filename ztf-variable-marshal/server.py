from aiohttp import web
import jinja2
import aiohttp_jinja2
from aiohttp_session import setup, get_session, session_middleware
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import aiofiles
import json
import jwt
from motor.motor_asyncio import AsyncIOMotorClient
from bson.json_util import loads, dumps
import datetime
import time
from ast import literal_eval
from async_timeout import timeout
import asyncio
# import concurrent.futures
from misaka import Markdown, HtmlRenderer
import os
import pathlib
import shutil
import re
import numpy as np
import string
import random
import traceback
from penquins import Kowalski

from utils import *


''' markdown rendering '''
rndr = HtmlRenderer()
md = Markdown(rndr, extensions=('fenced-code',))


''' load config and secrets '''
with open('/app/config.json') as cjson:
    config = json.load(cjson)

with open('/app/secrets.json') as sjson:
    secrets = json.load(sjson)

for k in secrets:
    if k in config:
        config[k].update(secrets.get(k, {}))
    else:
        config[k] = secrets[k]
# print(config)


async def init_db():
    _client = AsyncIOMotorClient(username=config['database']['admin'],
                                 password=config['database']['admin_pwd'],
                                 host=config['database']['host'],
                                 port=config['database']['port'])

    # _id: db_name.user_name
    user_ids = []
    async for _u in _client.admin.system.users.find({}, {'_id': 1}):
        user_ids.append(_u['_id'])

    print(user_ids)

    db_name = config['database']['db']
    username = config['database']['user']

    # print(f'{db_name}.{username}')
    # print(user_ids)

    _mongo = _client[db_name]

    if f'{db_name}.{username}' not in user_ids:
        await _mongo.command('createUser', config['database']['user'],
                             pwd=config['database']['pwd'], roles=['readWrite'])
        print('Successfully initialized db')

    _mongo.client.close()


async def add_admin(_mongo):
    """
        Create admin user for the web interface if it does not exists already
    :return:
    """
    ex_admin = await _mongo.users.find_one({'_id': config['server']['admin_username']})
    if ex_admin is None or len(ex_admin) == 0:
        try:
            await _mongo.users.insert_one({'_id': config['server']['admin_username'],
                                           'password': generate_password_hash(config['server']['admin_password']),
                                           'permissions': {},
                                           'last_modified': utc_now()
                                           })
        except Exception as e:
            print(f'Got error: {str(e)}')
            _err = traceback.format_exc()
            print(_err)


routes = web.RouteTableDef()


@web.middleware
async def auth_middleware(request, handler):
    """
        auth middleware
    :param request:
    :param handler:
    :return:
    """
    tic = time.time()
    request.user = None
    jwt_token = request.headers.get('authorization', None)

    if jwt_token:
        try:
            payload = jwt.decode(jwt_token, request.app['JWT']['JWT_SECRET'],
                                 algorithms=[request.app['JWT']['JWT_ALGORITHM']])
            # print('Godny token!')
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return web.json_response({'message': 'Token is invalid'}, status=400)

        request.user = payload['user_id']

    response = await handler(request)
    toc = time.time()
    # print(f"Auth middleware took {toc-tic} seconds to execute")

    return response


def auth_required(func):
    """
        Wrapper to ensure successful user authorization to use the API
    :param func:
    :return:
    """
    def wrapper(request):
        if not request.user:
            return web.json_response({'message': 'Auth required'}, status=401)
        return func(request)
    return wrapper


def login_required(func):
    """
        Wrapper to ensure successful user authorization to use the web frontend
    :param func:
    :return:
    """
    async def wrapper(request):
        # get session:
        session = await get_session(request)
        if 'jwt_token' not in session:
            # return web.json_response({'message': 'Auth required'}, status=401)
            # redirect to login page
            location = request.app.router['login'].url_for()
            # location = '/login'
            raise web.HTTPFound(location=location)
        else:
            jwt_token = session['jwt_token']
            if not await token_ok(request, jwt_token):
                # return web.json_response({'message': 'Auth required'}, status=401)
                # redirect to login page
                location = request.app.router['login'].url_for()
                # location = '/login'
                raise web.HTTPFound(location=location)
        return await func(request)
    return wrapper


async def token_ok(request, jwt_token):
    try:
        payload = jwt.decode(jwt_token, request.app['JWT']['JWT_SECRET'],
                             algorithms=[request.app['JWT']['JWT_ALGORITHM']])
        return True
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return False


@routes.post('/auth')
async def auth(request):
    try:
        post_data = await request.json()
    except Exception as _e:
        print(f'Cannot extract json() from request, trying post(): {str(_e)}')
        # _err = traceback.format_exc()
        # print(_err)
        post_data = await request.post()

    # print(post_data)

    # must contain 'username' and 'password'

    if ('username' not in post_data) or (len(post_data['username']) == 0):
        return web.json_response({'message': 'Missing "username"'}, status=400)
    if ('password' not in post_data) or (len(post_data['password']) == 0):
        return web.json_response({'message': 'Missing "password"'}, status=400)

    username = str(post_data['username'])
    password = str(post_data['password'])

    try:
        # user exists and passwords match?
        select = await request.app['mongo'].users.find_one({'_id': username})
        if check_password_hash(select['password'], password):
            payload = {
                'user_id': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=request.app['JWT']['JWT_EXP_DELTA_SECONDS'])
            }
            jwt_token = jwt.encode(payload,
                                   request.app['JWT']['JWT_SECRET'],
                                   request.app['JWT']['JWT_ALGORITHM'])

            return web.json_response({'token': jwt_token.decode('utf-8')})

        else:
            return web.json_response({'message': 'Wrong credentials'}, status=400)

    except Exception as e:
        print(f'Got error: {str(e)}')
        _err = traceback.format_exc()
        print(_err)
        return web.json_response({'message': 'Wrong credentials'}, status=400)


@routes.get('/login')
async def login_get(request):
    """
        Serve login page
    :param request:
    :return:
    """
    context = {'logo': config['server']['logo']}
    response = aiohttp_jinja2.render_template('template-login.html',
                                              request,
                                              context)
    return response


@routes.post('/login', name='login')
async def login_post(request):
    """
        Server login page for the browser
    :param request:
    :return:
    """
    try:
        try:
            post_data = await request.json()
        except Exception as _e:
            print(f'Cannot extract json() from request, trying post(): {str(_e)}')
            # _err = traceback.format_exc()
            # print(_err)
            post_data = await request.post()

        # get session:
        session = await get_session(request)

        if ('username' not in post_data) or (len(post_data['username']) == 0):
            return web.json_response({'message': 'Missing "username"'}, status=400)
        if ('password' not in post_data) or (len(post_data['password']) == 0):
            return web.json_response({'message': 'Missing "password"'}, status=400)

        username = str(post_data['username'])
        password = str(post_data['password'])

        # print(username, password)
        print(f'User {username} logged in.')

        # user exists and passwords match?
        select = await request.app['mongo'].users.find_one({'_id': username})
        if check_password_hash(select['password'], password):
            payload = {
                'user_id': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(
                    seconds=request.app['JWT']['JWT_EXP_DELTA_SECONDS'])
            }
            jwt_token = jwt.encode(payload,
                                   request.app['JWT']['JWT_SECRET'],
                                   request.app['JWT']['JWT_ALGORITHM'])

            # store the token, will need it
            session['jwt_token'] = jwt_token.decode('utf-8')
            session['user_id'] = username

            print('LOGIN', session)

            return web.json_response({'message': 'success'}, status=200)

        else:
            raise Exception('Bad credentials')

    except Exception as _e:
        print(f'Got error: {str(_e)}')
        _err = traceback.format_exc()
        print(_err)
        return web.json_response({'message': f'Failed to login user: {_err}'}, status=401)


@routes.get('/logout', name='logout')
async def logout(request):
    """
        Logout web user
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    session.invalidate()

    # redirect to login page
    location = request.app.router['login'].url_for()
    # location = '/login'
    raise web.HTTPFound(location=location)


@routes.get('/test')
@auth_required
async def handler_test(request):
    return web.json_response({'message': 'test ok.'}, status=200)


@routes.get('/test_wrapper')
@login_required
async def wrapper_handler_test(request):
    return web.json_response({'message': 'test ok.'}, status=200)


@routes.get('/', name='root')
@login_required
async def root_handler(request):
    """
        Serve home page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    context = {'logo': config['server']['logo'],
               'user': session['user_id']}
    response = aiohttp_jinja2.render_template('template-root.html',
                                              request,
                                              context)
    # response.headers['Content-Language'] = 'ru'
    return response


''' manage users: API '''


@routes.get('/users')
@login_required
async def manage_users(request):
    """
        Serve users page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    # only admin can access this
    if session['user_id'] == config['server']['admin_username']:
        users = await request.app['mongo'].users.find({}, {'password': 0}).to_list(length=1000)
        # print(users)

        context = {'logo': config['server']['logo'],
                   'user': session['user_id'],
                   'users': users}
        response = aiohttp_jinja2.render_template('template-users.html',
                                                  request,
                                                  context)
        return response

    else:
        return web.json_response({'message': '403 Forbidden'}, status=403)


@routes.put('/users')
@login_required
async def add_user(request):
    """
        Add new user to DB
    :return:
    """
    # get session:
    session = await get_session(request)

    _data = await request.json()
    # print(_data)

    if session['user_id'] == config['server']['admin_username']:
        try:
            username = _data['user'] if 'user' in _data else None
            password = _data['password'] if 'password' in _data else None
            permissions = _data['permissions'] if 'permissions' in _data else '{}'

            if len(username) == 0 or len(password) == 0:
                return web.json_response({'message': 'username and password must be set'}, status=500)

            if len(permissions) == 0:
                permissions = '{}'

            # add user to coll_usr collection:
            await request.app['mongo'].users.insert_one(
                {'_id': username,
                 'password': generate_password_hash(password),
                 'permissions': literal_eval(str(permissions)),
                 'last_modified': datetime.datetime.now()}
            )

            return web.json_response({'message': 'success'}, status=200)

        except Exception as _e:
            print(f'Got error: {str(_e)}')
            _err = traceback.format_exc()
            print(_err)
            return web.json_response({'message': f'Failed to add user: {_err}'}, status=500)
    else:
        return web.json_response({'message': '403 Forbidden'}, status=403)


@routes.delete('/users')
@login_required
async def remove_user(request):
    """
        Remove user from DB
    :return:
    """
    # get session:
    session = await get_session(request)

    _data = await request.json()
    # print(_data)

    if session['user_id'] == config['server']['admin_username']:
        try:
            # get username from request
            username = _data['user'] if 'user' in _data else None
            if username == config['server']['admin_username']:
                return web.json_response({'message': 'Cannot remove the superuser!'}, status=500)

            # try to remove the user:
            await request.app['mongo'].users.delete_one({'_id': username})

            return web.json_response({'message': 'success'}, status=200)

        except Exception as _e:
            print(f'Got error: {str(_e)}')
            _err = traceback.format_exc()
            print(_err)
            return web.json_response({'message': f'Failed to remove user: {_err}'}, status=500)
    else:
        return web.json_response({'message': '403 Forbidden'}, status=403)


@routes.post('/users')
@login_required
async def edit_user(request):
    """
        Edit user info
    :return:
    """
    # get session:
    session = await get_session(request)

    _data = await request.json()
    # print(_data)

    if session['user_id'] == config['server']['admin_username']:
        try:
            _id = _data['_user'] if '_user' in _data else None
            username = _data['edit-user'] if 'edit-user' in _data else None
            password = _data['edit-password'] if 'edit-password' in _data else None
            # permissions = _data['edit-permissions'] if 'edit-permissions' in _data else '{}'

            if _id == config['server']['admin_username'] and username != config['server']['admin_username']:
                return web.json_response({'message': 'Cannot change the admin username!'}, status=500)

            if len(username) == 0:
                return web.json_response({'message': 'username must be set'}, status=500)

            # change username:
            if _id != username:
                select = await request.app['mongo'].users.find_one({'_id': _id})
                select['_id'] = username
                await request.app['mongo'].users.insert_one(select)
                await request.app['mongo'].users.delete_one({'_id': _id})

            # change password:
            if len(password) != 0:
                await request.app['mongo'].users.update_one(
                    {'_id': username},
                    {
                        '$set': {
                            'password': generate_password_hash(password)
                        },
                        '$currentDate': {'last_modified': True}
                    }
                )

            # change permissions:
            # if len(permissions) != 0:
            #     select = await request.app['mongo'].users.find_one({'_id': username}, {'_id': 0, 'permissions': 1})
            #     # print(select)
            #     # print(permissions)
            #     _p = literal_eval(str(permissions))
            #     # print(_p)
            #     if str(permissions) != str(select['permissions']):
            #         result = await request.app['mongo'].users.update_one(
            #             {'_id': _id},
            #             {
            #                 '$set': {
            #                     'permissions': _p
            #                 },
            #                 '$currentDate': {'last_modified': True}
            #             }
            #         )

            return web.json_response({'message': 'success'}, status=200)

        except Exception as _e:
            print(f'Got error: {str(_e)}')
            _err = traceback.format_exc()
            print(_err)
            return web.json_response({'message': f'Failed to remove user: {_err}'}, status=500)
    else:
        return web.json_response({'message': '403 Forbidden'}, status=403)


''' sources API '''


@routes.get('/sources')
@login_required
async def sources_get_handler(request):
    """
        Serve saved sources page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    # todo: get last 10 added sources

    context = {'logo': config['server']['logo'],
               'user': session['user_id']}
    # fixme:
    response = aiohttp_jinja2.render_template('template.html',
                                              request,
                                              context)
    return response


@routes.put('/sources')
@login_required
async def sources_put_handler(request):
    """
        Save ZTF source to own db
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    try:
        _r = await request.json()
    except Exception as _e:
        print(f'Cannot extract json() from request, trying post(): {str(_e)}')
        _r = await request.post()
    # print(_r)

    try:
        assert '_id' in _r, '_id not specified'

        kowalski_query = {"query_type": "general_search",
                          "query": f"db['{config['kowalski']['coll_sources']}'].find({{'_id': {_r['_id']}}}, " +
                                   f"{{'_id': 1, 'ra': 1, 'dec': 1, 'filter': 1, 'coordinates': 1, 'data': 1}})"
                          }

        resp = request.app['kowalski'].query(kowalski_query)
        ztf_source = resp['result_data']['query_result'][0]

        # build doc to ingest:
        doc = dict()

        source_id_base = \
            f'ZTFS{datetime.datetime.utcnow().strftime("%y")}{ztf_source["coordinates"]["radec_str"][0][:2]}'

        num_saved_sources = await request.app['mongo'].sources.count_documents({'_id':
                                                                                    {'$regex': f'{source_id_base}.*'}})
        # postfix = num2alphabet(num_saved_sources + 1)
        if num_saved_sources > 0:
            saved_source_ids = await request.app['mongo'].sources.find({'_id': {'$regex': f'{source_id_base}.*'}},
                                                                        {'_id': 1}).to_list(length=None)
            saved_source_ids = [s['_id'] for s in saved_source_ids]
            # print(saved_source_ids)
            num_last = alphabet2num(sorted(saved_source_ids)[-1][8:])

            postfix = num2alphabet(num_last + 1)

        else:
            postfix = 'a'

        source_id = source_id_base + postfix

        doc['_id'] = source_id
        doc['ra'] = ztf_source['ra']
        doc['dec'] = ztf_source['dec']
        doc['coordinates'] = ztf_source['coordinates']
        # [{'period': float, 'period_error': float}]:
        doc['p'] = []
        doc['source_type'] = []
        # temporal, folded; if folded - 'p': [{'period': float, 'period_error': float}]
        lc = {'telescope': 'PO:1.2m',
              'instrument': 'ZTF',
              'filter': ztf_source['filter'],
              'lc_type': 'temporal',
              'data': ztf_source['data']}
        doc['lc'] = [lc]

        await request.app['mongo'].sources.insert_one(doc)

        return web.json_response({'message': 'success'}, status=200)

    except Exception as _e:
        print(f'Failed to ingest source: {str(_e)}')

        return web.json_response({'message': f'ingestion failed {str(_e)}'}, status=500)


''' search ZTF light curve db '''


@routes.get('/search')
@login_required
async def search_get_handler(request):
    """
        Serve GS page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    context = {'logo': config['server']['logo'],
               'user': session['user_id']}
    response = aiohttp_jinja2.render_template('template-search.html',
                                              request,
                                              context)
    return response


@routes.post('/search')
@login_required
async def search_post_handler(request):
    """
        Process Kowalski query
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    try:
        _query = await request.json()
    except Exception as _e:
        print(f'Cannot extract json() from request, trying post(): {str(_e)}')
        # _err = traceback.format_exc()
        # print(_err)
        _query = await request.post()
    print(_query)

    try:
        # convert to Kowalski query and execute

        kowalski_query = {"query_type": "cone_search",
                          "object_coordinates": {
                              "radec": _query['radec'],
                              "cone_search_radius": _query['cone_search_radius'],
                              "cone_search_unit": _query['cone_search_unit']
                          },
                          "catalogs": {
                              config['kowalski']['coll_sources']: {
                                  "filter": _query['filter'] if len(_query['filter']) > 0 else "{}",
                                  "projection": "{'_id': 1, 'ra': 1, 'dec': 1, 'magrms': 1, 'maxmag': 1," +
                                                "'vonneumannratio': 1, 'filter': 1," +
                                                "'maxslope': 1, 'meanmag': 1, 'medianabsdev': 1," +
                                                "'medianmag': 1, 'minmag': 1, 'ngoodobs': 1," +
                                                "'nobs': 1, 'refmag': 1, 'iqr': 1, " +
                                                "'data.mag': 1, 'data.magerr': 1, 'data.mjd': 1, 'coordinates': 1}"
                              }
                          }
                          }

        resp = request.app['kowalski'].query(kowalski_query)
        # print(resp)

        pos_key = list(resp['result_data'][config['kowalski']['coll_sources']].keys())[0]
        data = resp['result_data'][config['kowalski']['coll_sources']][pos_key]

        # re-format data (mjd, mag, magerr) for easier previews in the browser:
        for source in data:
            lc = source['data']
            # print(lc)
            mags = np.array([llc['mag'] for llc in lc])
            magerrs = np.array([llc['magerr'] for llc in lc])
            mjds = np.array([llc['mjd'] for llc in lc])
            datetimes = np.array([mjd_to_datetime(llc['mjd']).strftime('%Y-%m-%d %H:%M:%S') for llc in lc])

            ind_sort = np.argsort(mjds)
            mags = mags[ind_sort].tolist()
            magerrs = magerrs[ind_sort].tolist()
            mjds = mjds[ind_sort].tolist()
            datetimes = datetimes[ind_sort].tolist()

            source.pop('data', None)
            source['mag'] = mags
            source['magerr'] = magerrs
            # source['mjd'] = mjds
            source['mjd'] = datetimes

        # print(data)

        context = {'logo': config['server']['logo'],
                   'user': session['user_id'],
                   'data': data,
                   'form': _query}
        response = aiohttp_jinja2.render_template('template-search.html',
                                                  request,
                                                  context)
        return response

    except Exception as _e:
        print(f'Querying Kowalski failed: {str(_e)}')

        context = {'logo': config['server']['logo'],
                   'user': session['user_id'],
                   'messages': [[str(_e), 'danger']]}
        response = aiohttp_jinja2.render_template('template-search.html',
                                                  request,
                                                  context)
        return response


''' web endpoints '''


@routes.get('/docs')
@login_required
async def docs_handler(request):
    """
        Serve docs page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    # todo?

    context = {'logo': config['server']['logo'],
               'user': session['user_id']}
    response = aiohttp_jinja2.render_template('template-docs.html',
                                              request,
                                              context)
    return response


@routes.get('/docs/{doc}')
@login_required
async def doc_handler(request):
    """
        Serve doc page for the browser
    :param request:
    :return:
    """
    # get session:
    session = await get_session(request)

    doc = request.match_info['doc']

    title = doc.replace('_', ' ').capitalize()

    # render doc with misaka
    with open(os.path.join(config['path']['path_docs'],
                           doc + '.md'), 'r') as f:
        tut = f.read()

    content = md(tut)

    context = {'logo': config['server']['logo'],
               'user': session['user_id'],
               'title': title,
               'content': content}
    response = aiohttp_jinja2.render_template('template-doc.html',
                                              request,
                                              context)
    return response


async def app_factory():
    """
        App Factory
    :return:
    """

    # init db if necessary
    await init_db()

    # Database connection
    client = AsyncIOMotorClient(f"mongodb://{config['database']['user']}:{config['database']['pwd']}@" +
                                f"{config['database']['host']}:{config['database']['port']}/{config['database']['db']}")
    mongo = client[config['database']['db']]

    # add site admin if necessary
    await add_admin(mongo)

    # init app with auth middleware
    app = web.Application(middlewares=[auth_middleware])

    # store mongo connection
    app['mongo'] = mongo

    # make sure sources are 2d indexed
    await app['mongo'].sources.create_index([('coordinates.radec_geojson', '2dsphere'),
                                             ('_id', 1)], background=True)

    # graciously close mongo client on shutdown
    async def close_mongo(app):
        app['mongo'].client.close()

    app.on_cleanup.append(close_mongo)

    # Kowalski connection:
    app['kowalski'] = Kowalski(username=config['kowalski']['username'], password=config['kowalski']['password'])

    # set up JWT for user authentication/authorization
    app['JWT'] = {'JWT_SECRET': config['server']['JWT_SECRET_KEY'],
                  'JWT_ALGORITHM': 'HS256',
                  'JWT_EXP_DELTA_SECONDS': 30 * 86400 * 3}

    # render templates with jinja2
    aiohttp_jinja2.setup(app, loader=jinja2.FileSystemLoader('./templates'))

    # set up browser sessions
    fernet_key = config['misc']['fernet_key'].encode()
    secret_key = base64.urlsafe_b64decode(fernet_key)
    setup(app, EncryptedCookieStorage(secret_key))

    # route table
    # app.add_routes([web.get('/', hello)])
    app.add_routes(routes)

    # static files
    app.add_routes([web.static('/static', './static')])

    # data files
    app.add_routes([web.static('/data', '/data')])

    return app


''' Tests '''


class TestAPIs(object):
    # python -m pytest -s server.py
    # python -m pytest server.py

    # test user management API for admin
    async def test_users(self, aiohttp_client):
        client = await aiohttp_client(await app_factory(_config=config))

        login = await client.post('/login', json={"username": config['server']['admin_username'],
                                                  "password": config['server']['admin_password']})
        # print(login)
        assert login.status == 200

        # test = await client.get('/lab/ztf-alerts')
        # print(test)

        # adding a user
        resp = await client.put('/users', json={'user': 'test_user', 'password': random_alphanumeric_str(6)})
        assert resp.status == 200
        # text = await resp.text()
        # text = await resp.json()

        # editing user credentials
        resp = await client.post('/users', json={'_user': 'test_user',
                                                 'edit-user': 'test_user',
                                                 'edit-password': random_alphanumeric_str(6)})
        assert resp.status == 200
        resp = await client.post('/users', json={'_user': 'test_user',
                                                 'edit-user': 'test_user_edited',
                                                 'edit-password': ''})
        assert resp.status == 200

        # deleting a user
        resp = await client.delete('/users', json={'user': 'test_user_edited'})
        assert resp.status == 200

    # test programmatic query API
    async def test_query(self, aiohttp_client):
        # todo:
        client = await aiohttp_client(await app_factory(_config=config))

        # check JWT authorization
        auth = await client.post(f'/auth',
                                 json={"username": config['server']['admin_username'],
                                       "password": config['server']['admin_password']})
        assert auth.status == 200
        # print(await auth.text())
        # print(await auth.json())
        credentials = await auth.json()
        assert 'token' in credentials

        access_token = credentials['token']

        headers = {'Authorization': access_token}

        collection = 'ZTF_alerts'

        # check query without book-keeping
        qu = {"query_type": "general_search",
              "query": f"db['{collection}'].find_one({{}}, {{'_id': 1}})",
              "kwargs": {"save": False}
              }
        # print(qu)
        resp = await client.put('/query', json=qu, headers=headers, timeout=1)
        assert resp.status == 200
        result = await resp.json()
        assert result['status'] == 'done'

        # check query with book-keeping
        qu = {"query_type": "general_search",
              "query": f"db['{collection}'].find_one({{}}, {{'_id': 1}})",
              "kwargs": {"enqueue_only": True, "_id": random_alphanumeric_str(32)}
              }
        # print(qu)
        resp = await client.put('/query', json=qu, headers=headers, timeout=0.15)
        assert resp.status == 200
        result = await resp.json()
        # print(result)
        assert result['status'] == 'enqueued'

        # remove enqueued query
        resp = await client.delete('/query', json={'task_id': result['query_id']}, headers=headers, timeout=1)
        assert resp.status == 200
        result = await resp.json()
        assert result['message'] == 'success'


if __name__ == '__main__':

    web.run_app(app_factory(), port=config['server']['port'])
