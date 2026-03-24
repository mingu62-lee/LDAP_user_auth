# LDAP_user_auth
user id check in nginx

1. proxy서버에서 nginx를 이용하여 pip install 시 ldap에 등록된 유저가 어떤 패키지를 다운받는지 로그가 남을 수 있도록 한다.
2. auth.py는 daemon으로 monitoring하고 해당 프록시로 req가 들어왔을 때 nginx.conf파일의 변수를 읽어 로그에 쌓이도록 유도
