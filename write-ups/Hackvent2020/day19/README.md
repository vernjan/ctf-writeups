# HV20.19 Docker Linter Service

_Docker Linter is a useful web application ensuring that your Docker-related files follow best practices. Unfortunately, there's a security issue in there..._

## Requirements

_This challenge requires a reverse shell. You can use the provided Web Shell or the VPN to solve this challenge (see `RESOURCES` on top)._

_Note: The VPN connection information has been updated._

---

![](docker-linter.png)


- **Dockerfile**
    - [hadolint](https://github.com/hadolint/hadolint)
    - [dockerfile_lint](https://github.com/projectatomic/dockerfile_lint)
    - [dockerlint.js](https://www.npmjs.com/package/dockerlint)
- **docker-compose.yml**
    - Basic syntax check
    - yamllint
    - docker-compose
- **.env files**
    - [dotenv-linter](https://github.com/dotenv-linter/dotenv-linter)


