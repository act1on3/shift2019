# SHIFT AppSec 2019

## Stack
- Python3 + Flask
- Docker
- Git
- [uwsgi-nginx-flask-docker](https://github.com/tiangolo/uwsgi-nginx-flask-docker)
- Firefox
- Burp Suite
- some dependencies for python

### Install
#### Unix based


#### Windows


## How to work
Steps:
1) Regitser on [github.com](https://github.com)
2) Send me to telegram your nickname (or link at Github)
3) Clone repository
4) Create directory with your vulnerability (lowercase and `_`, e.g. `jwt_insecure`)
5) Copy `../example/README.md` into your folder
6) Use this directory and edit `README.md`

---
**Forbidden:**
- change files not in yours working (vulnerability) directories
- save non-text files
- don't translate specific definitions
---

## Cheat Sheet
### Git

Clone repo:
- `git clone https://github.com/act1on3/shift2019.git`

Fetch new info from remote origin:
- `git pull`

Add and commit changes:
- `git status`
- `git add <filename>`
- `git commit`
- write description of changes

Push local changes to origin:
- `git push`


### Docker
Build:
- `cd open_redirect`
- `docker build -t open_redirect .`
- `docker run -p 8080:80 open_redirect`

Close all containers:
- ```docker rm -f `docker ps -a -q` ```

Remove images:
- `docker images`
- `docker image rm <image_name>`