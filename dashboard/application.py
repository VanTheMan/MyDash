import dash
import dash_table
import pandas as pd
import dash_html_components as html
import dash_core_components as dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State
import boto3
import json
from flask import Flask
from flask import request as flask_request
import os
import logging
import jwt
import base64
import requests
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
import dash_table.FormatTemplate as FormatTemplate
from dash_table.Format import Sign, Scheme
from dash.exceptions import PreventUpdate
import numpy as np

logging.getLogger().setLevel(logging.INFO)

region = os.environ.get('DBREGION', 'us-east-1')

# This still needs to be implemented on the api side
environment = os.environ.get('DBENV', 'local')

server = Flask(__name__)

external_stylesheets = [dbc.themes.JOURNAL,
                        'https://codepen.io/chriddyp/pen/bWLwgP.css',
                        'table_dropdown.css']
app = dash.Dash(__name__, external_stylesheets=external_stylesheets, server=server)
# suppress_callback_exceptions=True

# Beanstalk looks for application by default, if this isn't set you will get a WSGI error.
application = app.server


# Add a route for the elastic beanstalk health check (this let's you know if the server is healthy)
@server.route("/health")
def health():
    return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


# Define global df
search_results_df = []
search_results_columns = ['hotbot', 'user_issue', 'geyser_issue']

spoof_search_df = pd.DataFrame({'Policy number': range(
    10), 'HotBot ID': range(10), 'Issue Status': range(10)})


def get_session():
    if environment == 'local':
        boto_session = boto3.Session(region_name=region, profile_name='personal')
    else:
        boto_session = boto3.Session(region_name=region)
    return boto_session


def generate_table(df, id):
    #  Top table
    table = dash_table.DataTable(
        id=id,
        filter_action='native',
        # seems to cause weird errors when used with page size that is smaller than the number of rows
        columns=[{"name": i, "id": i, "hideable": False} for i in df.columns],
        data=df.to_dict('records'),
        fixed_rows={'headers': True},
        # page_size=3,
        style_cell={
            'minWidth': 130,
            'width': 130,
            'maxWidth': 130,
            'textAlign': 'left',
            # 'overflow': 'hidden',
            'textOverflow': 'ellipsis',
            'whiteSpace': 'normal',
            'height': 'auto'
        },
        style_table={
            # 'height': '300px',
            # This messes with the bootstrap grid
            #  'width': '1000px',
            'overflowY': 'auto',
            'overflowX': 'auto'
        },
        tooltip_duration=0,
        # export_format='csv',
        # export_headers='display',
        merge_duplicate_headers=True,
        # row_selectable='multi',
        column_selectable='single',
        # selected_rows=[],
        sort_action="native",
        sort_mode='multi',
        style_as_list_view=True,
        style_header={
            'backgroundColor': 'white',
            'fontWeight': 'bold'
        },
        # editable=True,
    )

    table.tooltip_data = [
        {
            column: {'value': str(value), 'type': 'markdown'}
            for column, value in row.items()
        } for row in df.to_dict('records')
    ]

    return table


search_table = generate_table(spoof_search_df, 'search_table')


def generate_home_page():
    page = [

        # Header
        dbc.Row([
            dbc.Col(

                html.H1(id='dashboard',
                        children='mylittletrading',
                        style={
                            'textAlign': 'left',
                        }),
                width={"size": 'auto'}),

        ], no_gutters=True, justify="start"),

        # Log out
        dbc.Row([
            dbc.Col(

                html.Button('Log out', id='log_out'))

        ], no_gutters=True, justify="start"),

        # Create account
        dcc.Loading(
            type="dot",
            fullscreen=False,
            children=[
                html.Div([
                    html.Div(id='account_dummy1'),
                    html.Div(id='account_dummy2'),
                    dbc.Row([
                        dbc.Col([

                            dbc.Row([
                                dbc.Col(

                                    html.H2(children='Sign Up',
                                            style={
                                                'textAlign': 'left',
                                            }),

                                    width={"size": 'auto'}),
                            ], no_gutters=True, justify="start"),

                            # username
                            # dbc.Row([
                            #     dbc.Col(
                            #         'user name',
                            #         width={"size": 3, 'offset': 0}),
                            #
                            #     dbc.Col(
                            #         dcc.Input(id='username',
                            #                   style={'width': '100%'}),
                            #         width={"size": 4, 'offset': 0}),
                            #
                            # ], no_gutters=True, justify="start"),

                            # email
                            # dbc.Row([
                            #     dbc.Col(
                            #         'email',
                            #         width={"size": 3, 'offset': 0}),
                            #
                            #     dbc.Col(
                            #         dcc.Input(id='email',
                            #                   style={'width': '100%'},
                            #                   type='email'),
                            #         width={"size": 4, 'offset': 0}),
                            #
                            # ], no_gutters=True, justify="start"),

                            # phone number
                            # dbc.Row([
                            #     dbc.Col(
                            #         'phone number',
                            #         width={"size": 3, 'offset': 0}),
                            #
                            #     dbc.Col(
                            #         dcc.Input(id='phone_number',
                            #                   style={'width': '100%'},
                            #                   type='tel'),
                            #         width={"size": 4, 'offset': 0}),
                            #
                            # ], no_gutters=True, justify="start"),

                            dbc.Row([
                                dbc.Col(
                                    'binance api key',
                                    width={"size": 3, 'offset': 0}),

                                dbc.Col(
                                    dcc.Input(id='binance_api_key',
                                              style={'width': '100%'},
                                              type='password'),
                                    width={"size": 4, 'offset': 0}),

                            ], no_gutters=True, justify="start"),

                            dbc.Row([
                                dbc.Col(
                                    'binance_secret',
                                    width={"size": 3, 'offset': 0}),

                                dbc.Col(
                                    dcc.Input(id='binance_secret',
                                              style={'width': '100%'},
                                              type='password'),
                                    width={"size": 4, 'offset': 0}),

                            ], no_gutters=True, justify="start"),

                            dbc.Row([
                                dbc.Col(

                                    dcc.Checklist(id='us_account',
                                                  options=[
                                                      {'label': 'US account',
                                                       'value': 'US account'}
                                                  ],
                                                  value=['US account']),

                                    width={"size": 4, 'offset': 0}),
                            ], no_gutters=True, justify="start"),

                            dbc.Row([
                                dbc.Col(
                                    html.Button('Sign up', id='sign_up'),

                                    width={"size": 4, 'offset': 0}),
                            ], no_gutters=True, justify="start"),

                        ], width={"size": 4, 'offset': 0}),
                    ], no_gutters=True, justify="start")

                ], id='create_account', hidden=True),
            ]
        ),
        # Subscriptions

        html.Div([

            dcc.ConfirmDialog(
                id='confirm',
                message='You need to confirm your email subscription before you can delete it!',
            ),
            html.Div(id='alert_trigger'),

            dbc.Row([
                dbc.Col([

                    dbc.Row([
                        dbc.Col(

                            html.H2(children='Subscriptions',
                                    style={
                                        'textAlign': 'left',
                                    }),

                            width={"size": 'auto'}),
                    ], no_gutters=True, justify="start"),

                ],

                    width={"size": 12, 'offset': 0}),
            ], no_gutters=True, justify="start"),

            # Table is outside bootstrap components
            html.Div(id='highlight_trigger1'),
            html.Div(id='highlight_trigger2'),
            dcc.Loading(
                type="dot",
                fullscreen=False,
                children=[
                    html.Div(id='subscriptions')]),

            dcc.Interval(
                id='interval_component',
                interval=60 * 1000,  # in milliseconds
                n_intervals=0
            )

        ], id='subscriptions_container', hidden=True)

    ]

    return page


home_page = generate_home_page()

app.layout = dbc.Container(
    children=[html.Div(home_page, id='Home_page', hidden=False),
              dcc.Location(id='url', refresh=True, pathname='/')],
    fluid=True)


def get_verified_user_info(flask_rqst):
    # Get the info of authenticated user:
    # {'sub': 'eb2b6a7d-e1-4302-9953',
    #  'email_verified': 'true',
    #  'email': 'person@asdasd.co.za',
    #  'username': 'person',
    #  'exp': 1618586489,
    #  'iss': 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_6bR'}

    # Step 1: Get the key id from JWT headers (the kid field)
    encoded_jwt = flask_rqst.headers['x-amzn-oidc-data']
    jwt_headers = encoded_jwt.split('.')[0]
    decoded_jwt_headers = base64.b64decode(jwt_headers)
    decoded_jwt_headers = decoded_jwt_headers.decode("utf-8")
    decoded_json = json.loads(decoded_jwt_headers)
    kid = decoded_json['kid']

    # Step 2: Get the public key from regional endpoint
    url = 'https://public-keys.auth.elb.' + region + '.amazonaws.com/' + kid
    req = requests.get(url)
    pub_key = req.text

    # Step 3: Get the payload
    payload = jwt.decode(encoded_jwt, pub_key, algorithms=[decoded_json['alg']])

    logging.debug(f"JWT payload :{payload}")

    return payload


def get_decoded_access_token_payload():
    encoded_jwt = flask_request.headers['x-amzn-oidc-accesstoken']
    encoded_access_payload = encoded_jwt.split('.')[1]
    decoded_access_payload = base64.b64decode(bytes(encoded_access_payload, 'utf-8') + b'===')
    access_payload = decoded_access_payload.decode("utf-8")
    payload = json.loads(access_payload)

    logging.debug(f"Access payload :{payload}")

    return payload


@app.callback(
    Output('create_account', 'hidden'),
    Input('account_dummy1', 'children'),
    prevent_initial_call=False)
def show_sign_up(dummy):
    acc_table = os.environ.get('DBACCOUNTSTABLE', 'trd-ema-dep-accounts')

    if environment == 'local':
        email = 'test'
    else:
        jwt_payload = get_verified_user_info(flask_request)
        logging.error(jwt_payload)
        email = jwt_payload['email']

    boto_session = get_session()
    dynamodb = boto_session.resource('dynamodb')
    table = dynamodb.Table(acc_table)

    response = table.query(KeyConditionExpression=Key('email').eq(email), ScanIndexForward=False)

    logging.debug(response['Items'])

    if len(response['Items']) > 0:
        return True
    else:
        return False


@app.callback(
    Output('account_dummy1', 'children'),
    Input('sign_up', 'n_clicks'),
    State('binance_api_key', 'value'),
    State('binance_secret', 'value'),
    State('us_account', 'value'),
    prevent_initial_call=True)
def sign_up(n_clicks, binance_api_key, binance_secret, us_account):
    acc_table_name = os.environ.get('DBACCOUNTSTABLE', 'trd-ema-dep-accounts')

    if environment == 'local':
        email = 'test'
        username = 'test'
        phone_number = '123456789'
    else:
        jwt_payload = get_verified_user_info(flask_request)
        email = jwt_payload['email']
        username = jwt_payload['username']
        phone_number = jwt_payload['phone_number']

    boto_session = get_session()
    dynamodb = boto_session.resource('dynamodb')
    acc_table = dynamodb.Table(acc_table_name)

    item = {
        'user_name': username,
        'email': email,
        'phone_number': phone_number,
        'usa': True if len(us_account) > 0 and us_account[0] == 'US account' else False,
        'binance_key': binance_api_key,
        'binance_secret': binance_secret
    }

    logging.debug(item)
    response = acc_table.put_item(Item=item)
    logging.debug(response)

    return []


@app.callback(
    Output('url', 'href'),
    Input('log_out', 'n_clicks'),
    prevent_initial_call=True)
def log_out(n_clicks):
    if environment != 'local':
        # This is global sign out, i.e. invalidates all refresh tokens
        # client = session.client("cognito-idp")
        # access_tkn = flask_request.headers['x-amzn-oidc-accesstoken']
        # response = client.global_sign_out(AccessToken=access_tkn)
        # logging.debug("Successfully signed out!")

        expire = datetime.now()
        # Expire the ALB authentication session cookie
        dash.callback_context.response.set_cookie('AWSELBAuthSessionCookie-0',
                                                  value='INVALID',
                                                  expires=expire.strftime("%a, %d-%b-%Y %H:%M:%S UTC"))
        logging.debug("Successfully deleted session cookies!")
        # Redirect to cognito logout page to expire the cognito session cookie
        return f'https://{os.environ.get("DBCOGNITODOMAIN")}.auth.{region}.amazoncognito.com/logout?client_id={os.environ.get("DBCOGNITOCLIENTID")}&logout_uri={os.environ.get("DBDNS")}'
    else:
        return ''


@app.callback(
    Output('strategies_table', 'style_data_conditional'),
    Input('highlight_trigger1', 'children'),
    Input('highlight_trigger2', 'children'),
    State('strategies_table', 'data'),
    prevent_initial_call=True)
def highlight_selected_rows(trigger1, trigger2, data):
    balance_table_name = os.environ.get('DBBALANCETABLE', 'trd-ema-dep-balances')

    if environment == 'local':
        email = 'test'
    else:
        email = get_verified_user_info(flask_request)['email']

    boto_session = get_session()
    dynamodb = boto_session.resource('dynamodb')

    balance_table = dynamodb.Table(balance_table_name)
    response = balance_table.query(KeyConditionExpression=Key('email').eq(email),
                                   ScanIndexForward=False)

    logging.debug(f'Balances are {response["Items"]}')
    balances_df = pd.DataFrame(response["Items"])

    defaults = [
        {
            'if': {
                'column_id': 'target_usd',
            },
            'color': 'forestgreen',
        },
        {
            'if': {
                'column_id': 'delta_usd',
            },
            'color': 'forestgreen'
        },
        {
            'if': {
                'state': 'active'  # 'active' | 'selected'
            },
            'backgroundColor': 'rgba(0, 116, 217, 0.3)',
            'border': '1px solid rgb(0, 116, 217)',
            'textAlign': 'left'
        },
        {
            'if': {
                'column_editable': False  # True | False
            },
            'backgroundColor': 'rgb(240, 240, 240)',
            'cursor': 'not-allowed'
        },
    ]

    if len(balances_df) != 0:
        selected = [row['symbol'] in list(balances_df['symbol']) for row in data]
        selected_rows = np.arange(0, len(selected))[selected]
        return defaults + [
            {
                'if': {
                    'column_id': 'target_usd',
                    'row_index': i
                },
                'backgroundColor': 'beige',
                'color': 'forestgreen'
            } for i in selected_rows] + [
                   {
                       'if': {
                           'column_id': 'delta_usd',
                           'row_index': i
                       },
                       'backgroundColor': 'beige',
                       'color': 'forestgreen'
                   } for i in selected_rows] + [
                   {
                       'if': {
                           'column_id': 'sms_notify',
                           'row_index': i
                       },
                       'backgroundColor': 'beige',
                       'color': 'white'
                   } for i in selected_rows] + [
                   {
                       'if': {
                           'column_id': 'email_notify',
                           'row_index': i
                       },
                       'backgroundColor': 'beige',
                       'color': 'white'
                   } for i in selected_rows]

    return defaults


@app.callback(
    Output('subscriptions', 'children'),
    Output('subscriptions_container', 'hidden'),
    Output('highlight_trigger1', 'children'),
    Input('create_account', 'hidden'),
    Input('interval_component', 'n_intervals'),
    prevent_initial_call=False)
def get_subscriptions(create_account_hidden, n):
    """
    Initialisation of the subscriptions table
    :param create_account_hidden: parameter showing if account section is hidden or not
    :return: table
    """

    if not create_account_hidden:
        return [], True, []

    strat_table_name = os.environ.get('DBSTRATEGIESTABLE', 'trd-ema-dep-strategies')
    balance_table_name = os.environ.get('DBBALANCETABLE', 'trd-ema-dep-balances')

    if environment == 'local':
        email = 'test'
    else:
        email = get_verified_user_info(flask_request)['email']

    boto_session = get_session()
    dynamodb = boto_session.resource('dynamodb')

    balance_table = dynamodb.Table(balance_table_name)
    response = balance_table.query(KeyConditionExpression=Key('email').eq(email),
                                   ScanIndexForward=False)

    logging.debug(f'Balances are {response["Items"]}')
    balances_df = pd.DataFrame(response["Items"])

    strat_table = dynamodb.Table(strat_table_name)
    # Fix with recursive scan
    response = strat_table.scan()
    strategies_df = pd.DataFrame(response["Items"])
    logging.debug(f'All strategies are \n {strategies_df}')

    df = strategies_df.merge(balances_df, on='symbol', how='outer') if len(balances_df) > 0 else strategies_df
    # df.drop(columns=['symbol'], inplace=True)

    if len(balances_df) == 0:
        df['quantity_usd'] = 0
        df['quantity_symbol'] = 0
        df['target_usd'] = -1
        df['delta_usd'] = 0
        df['sms_arn'] = 'No'
        df['email_arn'] = 'No'

    df['quantity_usd'].fillna(0, inplace=True)
    df['quantity_symbol'].fillna(0, inplace=True)
    df['target_usd'].fillna(-1, inplace=True)
    df['delta_usd'].fillna(0, inplace=True)
    df['sms_arn'].fillna('No', inplace=True)
    df['email_arn'].fillna('No', inplace=True)

    df.loc[df['sms_arn'] != 'No', 'sms_notify'] = 'Yes'
    df.loc[df['email_arn'] != 'No', 'email_notify'] = 'Yes'
    df['sms_notify'].fillna('No', inplace=True)
    df['email_notify'].fillna('No', inplace=True)

    # df[['symbol']] = df[['symbol']].applymap(lambda x: x.replace(x.split('_')[0] + '_', ''))

    df = df[['symbol', 'quantity_usd', 'quantity_symbol', 'target_usd', 'delta_usd', 'sms_notify', 'email_notify']]

    table_dash = generate_table(df, 'strategies_table')

    for c in table_dash.columns:
        if c['name'] in ['quantity_usd', 'quantity_symbol']:
            c['type'] = 'numeric'

    for c in table_dash.columns:
        if c['name'] in ['target_usd', 'delta_usd']:
            c['editable'] = True
            c['type'] = 'numeric'
            c['format'] = FormatTemplate.money(0, sign=Sign.positive)

    for c in table_dash.columns:
        if c['name'] == 'sms_notify' or c['name'] == 'email_notify':
            c['presentation'] = 'dropdown'
            c['editable'] = True

    table_dash.dropdown = {
        'sms_notify': {
            'clearable': False,
            'options': [
                {'label': i, 'value': i} for i in ['No', 'Yes']
            ]
        },
        'email_notify': {
            'clearable': False,
            'options': [
                {'label': i, 'value': i} for i in ['No', 'Yes']
            ]
        }
    }

    return table_dash, False, []


def get_topic(strat_table, row):
    response = strat_table.scan()
    strategies_df = pd.DataFrame(response["Items"])
    symbol = strategies_df[strategies_df['symbol'] == row['symbol']]['symbol'].values[0]

    # Create SNS topic ARN that corresponds to symbol being traded
    topic = f'arn:aws:sns:us-east-1:1234567989:trd-ema-scheduler-{symbol}'

    return topic


@app.callback(
    Output('strategies_table', 'data'),
    Output('highlight_trigger2', 'children'),
    Output('alert_trigger', 'children'),
    Input('strategies_table', 'data_timestamp'),
    State('strategies_table', 'data_previous'),
    State('strategies_table', 'data'),
    prevent_initial_call=False)
def update_balances(timestamp, rows_prev, rows):
    """
    Responds to changes in target, delta, and notifications on subscriptions table
    :param timestamp: detects changes to table
    :param rows_prev: table before changes
    :param rows: table after changes
    :return: just a placeholder
    """

    balance_table_name = os.environ.get('DBBALANCETABLE', 'trd-ema-dep-balances')
    strat_table_name = os.environ.get('DBSTRATEGIESTABLE', 'trd-ema-dep-strategies')

    if environment == 'local':
        email = 'test'
        phone_number = '123456789'
    else:
        jwt_payload = get_verified_user_info(flask_request)
        email = jwt_payload['email']
        phone_number = jwt_payload['phone_number']

    delete_successful = True

    if rows_prev is not None:
        for r in range(len(rows)):
            if rows_prev[r] != rows[r]:

                sms_changed = rows_prev[r]['sms_notify'] != rows[r]['sms_notify']
                email_changed = rows_prev[r]['email_notify'] != rows[r]['email_notify']

                if sms_changed and rows[r]['sms_notify'] == 'Yes' or \
                        email_changed and rows[r]['email_notify'] == 'Yes':

                    boto_session = get_session()
                    dynamodb = boto_session.resource('dynamodb')
                    strat_table = dynamodb.Table(strat_table_name)

                    client = boto_session.client('sns')
                    sms_arn = rows[r]['sms_notify']
                    email_arn = rows[r]['email_notify']

                    # SMS notification is activated
                    if sms_changed and rows[r]['sms_notify'] == 'Yes':
                        logging.debug(f'phone number is {phone_number}')

                        sns_response = client.subscribe(
                            TopicArn=get_topic(strat_table, rows[r]),
                            Protocol='sms',
                            Endpoint=phone_number,
                            ReturnSubscriptionArn=True
                        )

                        sms_arn = sns_response['SubscriptionArn']

                    # email notification is activated
                    elif email_changed and rows[r]['email_notify'] == 'Yes':
                        logging.debug(f'email address is {email}')

                        sns_response = client.subscribe(
                            TopicArn=get_topic(strat_table, rows[r]),
                            Protocol='email',
                            Endpoint=email,
                            ReturnSubscriptionArn=True
                        )

                        email_arn = sns_response['SubscriptionArn']

                    logging.debug(sns_response)

                    balance_table = dynamodb.Table(balance_table_name)
                    balance_response = balance_table.query(
                        KeyConditionExpression=Key('email').eq(email) & Key('symbol').eq(
                            rows[r]["symbol"]),
                        ScanIndexForward=False)

                    # First entry in table, thus add whole item
                    if len(balance_response["Items"]) == 0:

                        item = {
                            'email': email,
                            'symbol': rows[r]['symbol'],
                            'quantity_usd': rows[r]['quantity_usd'],
                            'quantity_symbol': rows[r]['quantity_symbol'],
                            'target_usd': rows[r]['target_usd'],
                            'delta_usd': rows[r]['delta_usd'],
                            'sms_arn': sms_arn,
                            'email_arn': email_arn
                        }

                        response = balance_table.put_item(Item=item)

                    else:

                        # SMS notifcation is activated
                        if sms_changed and rows[r]['sms_notify'] == 'Yes':
                            response = balance_table.update_item(
                                Key={
                                    'email': email,
                                    'symbol': rows[r]['symbol']
                                },
                                UpdateExpression="set sms_arn = :r",
                                ExpressionAttributeValues={
                                    ':r': sns_response['SubscriptionArn'],
                                },
                                ReturnValues="UPDATED_NEW"
                            )

                        # email notifcation is activated
                        if email_changed and rows[r]['email_notify'] == 'Yes':
                            response = balance_table.update_item(
                                Key={
                                    'email': email,
                                    'symbol': rows[r]['symbol']
                                },
                                UpdateExpression="set email_arn = :r",
                                ExpressionAttributeValues={
                                    ':r': sns_response['SubscriptionArn'],
                                },
                                ReturnValues="UPDATED_NEW"
                            )

                    logging.debug(response)

                elif rows_prev[r]['sms_notify'] != rows[r]['sms_notify'] and rows[r]['sms_notify'] == 'No' or \
                        rows_prev[r]['email_notify'] != rows[r]['email_notify'] and rows[r]['email_notify'] == 'No':

                    boto_session = get_session()
                    dynamodb = boto_session.resource('dynamodb')

                    balance_table = dynamodb.Table(balance_table_name)
                    response = balance_table.query(KeyConditionExpression=Key('email').eq(email),
                                                   ScanIndexForward=False)
                    logging.debug(response)

                    balances_df = pd.DataFrame(response["Items"])

                    # sms notification is deactivated
                    if sms_changed and rows[r]['sms_notify'] == 'No':
                        subscription_arn = \
                            balances_df[balances_df['symbol'] == rows[r]['symbol']]['sms_arn'].values[0]

                    # email notification is deactivated
                    elif email_changed and rows[r]['email_notify'] == 'No':
                        subscription_arn = \
                            balances_df[balances_df['symbol'] == rows[r]['symbol']]['email_arn'].values[0]

                    delete_successful = True
                    try:
                        client = boto_session.client('sns')
                        response = client.unsubscribe(
                            SubscriptionArn=subscription_arn
                        )

                        logging.debug(response)
                    except:
                        print('You have to verify subscription before it can be deleted!')
                        rows[r]['email_notify'] = 'Yes'
                        delete_successful = False

                    # sms notification is deactivated
                    if sms_changed and rows[r]['sms_notify'] == 'No':
                        response = balance_table.update_item(
                            Key={
                                'email': email,
                                'symbol': rows[r]['symbol']
                            },
                            UpdateExpression="set sms_arn = :r",
                            ExpressionAttributeValues={
                                ':r': 'No',
                            },
                            ReturnValues="UPDATED_NEW"
                        )

                    # Notification is deactivated # Note that email notifcations can only be deleted once confirmed
                    elif email_changed and rows[r]['email_notify'] == 'No' and delete_successful:
                        response = balance_table.update_item(
                            Key={
                                'email': email,
                                'symbol': rows[r]['symbol']
                            },
                            UpdateExpression="set email_arn = :r",
                            ExpressionAttributeValues={
                                ':r': 'No',
                            },
                            ReturnValues="UPDATED_NEW"
                        )

                    logging.debug(response)

                # target_usd or delta_usd was changed
                elif rows_prev[r]['target_usd'] != rows[r]['target_usd'] or rows_prev[r]['delta_usd'] != rows[r][
                    'delta_usd']:
                    boto_session = get_session()
                    dynamodb = boto_session.resource('dynamodb')
                    balance_table = dynamodb.Table(balance_table_name)

                    balance_response = balance_table.query(
                        KeyConditionExpression=Key('email').eq(email) & Key('symbol').eq(
                            rows[r]["symbol"]),
                        ScanIndexForward=False)

                    # Add entry if table is empty
                    if len(balance_response["Items"]) == 0:

                        item = {
                            'email': email,
                            'symbol': rows[r]['symbol'],
                            'quantity_usd': rows[r]['quantity_usd'],
                            'quantity_symbol': rows[r]['quantity_symbol'],
                            'target_usd': rows[r]['target_usd'],
                            'delta_usd': rows[r]['delta_usd'],
                            'sms_arn': rows[r]['sms_notify'],
                            'email_arn': rows[r]['email_notify']
                        }

                        response = balance_table.put_item(Item=item)

                    # Otherwise just update the necessary attribute
                    else:

                        if rows_prev[r]['target_usd'] != rows[r]['target_usd']:

                            response = balance_table.update_item(
                                Key={
                                    'email': email,
                                    'symbol': rows[r]['symbol']
                                },
                                UpdateExpression="set target_usd = :r",
                                ExpressionAttributeValues={
                                    ':r': rows[r]['target_usd'],
                                },
                                ReturnValues="UPDATED_NEW"
                            )

                        elif rows_prev[r]['delta_usd'] != rows[r]['delta_usd']:

                            response = balance_table.update_item(
                                Key={
                                    'email': email,
                                    'symbol': rows[r]['symbol']
                                },
                                UpdateExpression="set delta_usd = :r",
                                ExpressionAttributeValues={
                                    ':r': rows[r]['delta_usd'],
                                },
                                ReturnValues="UPDATED_NEW"
                            )

                    logging.debug(response)

                # Check if values are default then delete from table
                if str(rows[r]['quantity_usd']) == '0' and \
                        str(rows[r]['quantity_symbol']) == '0' and \
                        rows[r]['target_usd'] < 0 and \
                        rows[r]['delta_usd'] == 0 and \
                        rows[r]['sms_notify'] == 'No' and \
                        rows[r]['email_notify'] == 'No':
                    boto_session = get_session()
                    dynamodb = boto_session.resource('dynamodb')
                    balance_table = dynamodb.Table(balance_table_name)

                    response = balance_table.delete_item(
                        Key={
                            'email': email,
                            'symbol': rows[r]['symbol']
                        }
                    )

                    logging.debug(response)

    return rows, [], not delete_successful
    # raise PreventUpdate


@app.callback(Output('confirm', 'displayed'),
              Input('alert_trigger', 'children'))
def display_confirm(value):
    if bool(value):
        return True
    return False


if __name__ == '__main__':
    port = int(os.environ.get('DBPORT', 8080))
    environment = os.environ.get('DBENV', 'local')
    debug = True if environment == 'local' else False

    # Can either be multi threaded or multi processing, but not both
    app.run_server(host='localhost', debug=debug, port=port, threaded=True)
