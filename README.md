# Alexa Slack

[![build status](https://git.cssnr.com/shane/alexa-slack-oauth/badges/master/build.svg)](https://git.cssnr.com/shane/alexa-slack-oauth/commits/master) [![coverage report](https://git.cssnr.com/shane/alexa-slack-oauth/badges/master/coverage.svg)](https://git.cssnr.com/shane/alexa-slack-oauth/commits/master)

Oauth endpoint for alexa-slack.

## Overview

Amazon Alexa built-in account linking does not work with all oauth endpoints. 
This endpoint negotiates the oauth with Slack, then returns the `access_token` 
to Amazon to store with the account for use with the Skill.

### Documentation

Alexa: https://developer.amazon.com/docs/custom-skills/link-an-alexa-user-with-a-user-in-your-system.html
Slack:  https://api.slack.com/docs/oauth
