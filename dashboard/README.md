# Getting started with dash

## Official documentation 

    https://dash.plotly.com/introduction
    https://dash-bootstrap-components.opensource.faculty.ai/docs/components/layout/

## Develop locally

### Use python 3.7 for development or higher

The beanstalk environment is set up to use python 3.7 

### Install the dependencies

Run the following command to install all the necessary python dependencies 

    pip install -r requirements.txt

### Run file
To run locally, you just execute the application.py file

    python application.py

Note any updates that you make to the code while the app is running locally will automatically be updated on the dashboard without needing you to rerun application.py

### Git
#### Create a new branch on git to develop on

    git branch <you_branch_name>

#### Checkout new branch

    git checkout <you_branch_name>
    
#### Commit your files

    git commit -a -m '<ADd message here>'
    
#### Push changes to remote

    git push --set-upstream origin <you_branch_name>

#### Merge with master (this will automatically deploy to AWS Beanstalk)    
    
    git checkout master
    git merge <you_branch_name>

#### Deployed URL is 

##### Production    
    https://mylittletrading.com/
##### Develop
    tbd

#### Authentication

##### Authentication payload example

    {'sub': 'eb2b6a7d-eb51-4302-9953', 
    'email_verified': 'true', 
    'email': 'person@personal.co.za', 
    'username': 'person', 
    'exp': 1618586489, 
    'iss': 'https://cognito-idp.$Region.amazonaws.com/$Region_6bxR'}

##### Access token  payload example
    {'sub': 'eb2b6a7d-e1-4302-9953', 
    'token_use': 'access', 
    'scope': 'aws.cognito.signin.user.admin openid profile email', 
    'auth_time': 1618867578, 
    'iss': 'https://cognito-idp.$Region.amazonaws.com/$Region_6bx85SPpR', 
    'exp': 1618871178, 
    'iat': 1618867578, 'version': 2, 
    'jti': 'b9e9d06c-c735-4287-a7f3-151f0bf857', 
    'client_id': '11jq3e20jp4qielr', 
    'username': 'asdqwe'}

##### The authentication takes place on the application load balancer 
- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html#authentication-logout-timeout
- https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html

###### In order to log out, you need to invalidate two http sessions 

- a session with the load balancer linked to the dashboard domain
- a session with cognito linked to the cognito domain (login page)

You can verify these on your browser.

Both these sessions needs to be invalidated (expired). The load balancer's session cookie can be expired manually in code
as you will be able to modify the cookies linked to the dashboard domain from which you are receiving requests, 
but you need to redirect to 
    
    GET https://mydomain.auth.us-east-1.amazoncognito.com/logout?client_id=ad398u21ijw939&logout_uri=https://myclient/logout

to invalidate the cognito session/access token. Yopu must do the invalidation in the order specified above.

# AWS infrastructure (Everything here is take care of by the CI/CD pipeline)
##Parameter

    Region=us-east-1

## Pipeline 
### Dependencies
#### Validate
    aws cloudformation validate-template \
        --template-body file://build_pipeline/pipeline_dependencies.yaml \
        --profile personal
#### Deploy
    aws cloudformation deploy \
            --region $Region \
            --template-file build_pipeline/pipeline_dependencies.yaml \
            --stack-name db-pl-dep \
            --force-upload \
            --capabilities CAPABILITY_NAMED_IAM \
            --profile personal

### Pipeline
#### Validate
    aws cloudformation validate-template \
        --template-body file://build_pipeline/pipeline_main.yaml \
        --profile personal
#### Deploy
    env=dev
    aws cloudformation deploy \
            --region $Region \
            --template-file build_pipeline/pipeline_main.yaml \
            --stack-name db-pl-$env \
            --force-upload \
            --capabilities CAPABILITY_NAMED_IAM \
            --profile personal \
            --parameter-overrides SourceFile=packaged_$branch.zip \
                Env=$env

## Dashboard
### Dependencies
#### Validate
    aws cloudformation validate-template \
        --template-body file://template_dependencies.yaml \
        --profile personal
#### Deploy
    aws cloudformation deploy \
            --region $Region \
            --template-file template_dependencies.yaml \
            --stack-name db-dep \
            --force-upload \
            --capabilities CAPABILITY_NAMED_IAM \
            --profile personal

### Dashboard
#### package and upload to s3 (you need to git commit your code before running these!)
    current_time=$(date +'%s')
    env=dev
    git archive -v -o "python-dashboard-$current_time.zip" --format=zip HEAD
    aws s3 cp "python-dashboard-$current_time.zip" "s3://db-dep-$Region/$env/"
    rm "python-dashboard-$current_time.zip"

##### Or

    current_time=$(date +'%s')
    env=prod
    zip python-dashboard-$current_time.zip -r * .[^.]*
    aws s3 cp "python-dashboard-$current_time.zip" "s3://db-dep-$Region/$env/" --profile personal
    rm "python-dashboard-$current_time.zip"

##### Validate
    aws cloudformation validate-template \
        --template-body file://template.yaml \
        --profile personal
##### Deploy
    aws cloudformation deploy \
            --profile personal \
            --region $Region \
            --template-file template.yaml \
            --stack-name db-$env \
            --force-upload \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameter-overrides "Date=$current_time" "Env=$env"
            
### Cognito
##### Validate
    aws cloudformation validate-template \
        --template-body file://template_cognito.yaml \
        --profile personal
##### Deploy
    env=prod
    aws cloudformation deploy \
            --profile personal \
            --region $Region \
            --template-file template_cognito.yaml \
            --stack-name db-cognito-$env \
            --force-upload \
            --capabilities CAPABILITY_NAMED_IAM \
            --parameter-overrides "Env=$env"