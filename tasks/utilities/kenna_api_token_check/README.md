# Verifying Kenna API Key

This task utility verifies the Kenna API key, also referred to as token, to a specific Kenna host.

## Usage
`task=kenna_api_key_check kenna_api_key=<API-Key> [api_host=<api_host] [show_api_key=<yes|no>]

* api_host is optional and defaults to `api.kennasecurity.com`.
* show_api_key is optional and defaults to `no`.

if <show_api_key> is `yes`, then the full value of the Kenna API key is displayed.  This is considered unsecure.

## Results

As part of the toolkit, as secure version on the API key and the Kenna host. 
After that the number of connectors, users, roles, asset groups (risk meters), and vulnerabilities are displayed.

```
> docker run -it kennasecurity/toolkit task=kenna_api_key_check kenna_api_key=$KENNA_API_KEY
Running: Kenna::Toolkit::KennaApiTokenCheck
[+] (20230227192955) Setting kenna_api_host to default value: api.kennasecurity.com
[+] (20230227192955) Got option: task: kenna_api_key_check
[+] (20230227192955) Got option: kenna_api_key: 1*******tXq
[+] (20230227192955) Got option: kenna_api_host: api.kennasecurity.com
[+] (20230227192955) 
[+] (20230227192955) Launching the Kenna API Token Check task!
[+] (20230227192956) 
[+] (20230227192956) Connectors: 3
[+] (20230227192957) Users: 224
[+] (20230227192957) Roles: 21
[+] (20230227193002) Asset Groups: 2
[+] (20230227193002) Vulns: 143
```

If an HTTP `401 Unauthorized` status code is returned, then verifying the value of the Kenna API key could prove useful.  To verify the value of the Kenna API key, type in:

```
> docker run -it kennasecurity/toolkit task=kenna_api_key_check kenna_api_key=$KENNA_API_KEY show_api_key=yes
[+] (20230306151130) Setting kenna_api_host to default value: api.kennasecurity.com
[+] (20230306151130) Setting show_api_key to default value: no
[+] (20230306151130) Got option: task: kenna_api_key_check
[+] (20230306151130) Got option: kenna_api_key: 1*******tXq
[+] (20230306151130) Got option: show_api_key: y*******yes
[+] (20230306151130) Got option: kenna_api_host: api.kennasecurity.com
[+] (20230306151130) 
[+] (20230306151130) Launching the Kenna API Token Check task!
[+] (20230306151131) 
[ ] (20230306151131) Kenna API key: 2xTEfWtFB2yp4KYp2sWfLuRr13-9PqQu47jsAKQk5yDJMvXYjribhdY9t81EmtXq
[+] (20230306151131) Connectors: 3
[+] (20230306151132) Users: 226
[+] (20230306151133) Roles: 21
[+] (20230306151133) Asset Groups: 2
[+] (20230306151133) Vulns: 143
```

**Note:** Showing the value of the Kenna API key is considered **insecure**.

