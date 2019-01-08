# SHIFT AppSec 2019

## Docker
Build:
- `cd open_redirect`
- `docker build -t open_redirect .`
- `docker run -p 8080:80 open_redirect`

Close all containers:
- ```docker rm -f `docker ps -a -q` ```

Remove images:
- `docker images`
- `docker image rm <image_name>`
