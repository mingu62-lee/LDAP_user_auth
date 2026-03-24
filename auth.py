from flask import Flask, request, abort, Response
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, NTLM, SIMPLE
import base64
import jwt
app = Flask(__name__)

@app.route("/ldap-auth", methods=["GET"])
def ldap_auth():
        ldap_url = request.headers.get("X-Ldap-URL")
        base_dn = request.headers.get("X-Ldap-BaseDN")
        bind_dn = request.headers.get("X-Ldap-BindDN")
        bind_pw = request.headers.get("X-Ldap-BindPass")
        search_filter_template = request.headers.get("X-Ldap-SearchFilter")
        #auth = request.headers.get("Authorization")
        #print(f"{ldap_url}")
        #realm = request.headers.get("X-Auth-Realm", "Authentication Required")
        auth_header = request.headers.get("Authorization", "")
        path = request.headers.get("X-Original-URI", "")
        #docker
        if path.startswith("/v2/"):
                if auth_header.startswith("Basic "):
                        encoded = auth_header.split(" ",1)[1]
                        decoded = base64.b64decode(encoded).decode()
                        username, password = decoded.split(":", 1)
                        if ldapauth(username, password, ldap_url, base_dn, bind_dn, bind_pw, search_filter_template):
                                return ("", 200, {"X-Authenticated-User": username})
                        return ("", 401)
                elif auth_header.startswith("Bearer "):
                        token = auth_header.split(" ",1)[1]
                        username = extract_username_from_token(token)
                        if username:
                                return ("", 200, {"X-Authenticated-User": username})
                        return ("", 401)
                return ("", 401)


        #normal
        if auth_header.startswith("Basic "):
                encoded = auth_header.split(" ",1)[1]
                decoded = base64.b64decode(encoded).decode()
                username, password = decoded.split(":", 1)
                if ldapauth(username, password, ldap_url, base_dn, bind_dn, bind_pw, search_filter_template):
                        return ("", 200, {"X-Authenticated-User": username})
        return ("", 401)


        #if not auth or not auth.startswith("Basic "):
        #       print(f"[ERROR] Invalid credentials for 1 ")
        #       return Response("unauthorized",status=401,headers={"WWW-Authenticate": f'Basic realm="{realm}"'})
                #abort(401)
        # 사용자 인증 정보 파싱
        #try:
        #       userpass = base64.b64decode(auth.split(" ")[1]).decode("utf-8")
        #       username, password = userpass.split(":", 1)
        #except Exception as e:
        #       print(f"[ERROR] Invalid credentials for 2 {e}")
        #       return Response("unauthorized",status=401,headers={"WWW-Authenticate": f'Basic realm="{realm}"'})

def ldapauth(username, password, ldap_url, base_dn, bind_dn, bind_pw, search_filter_template):
        # LDAP 서버 연결
        server = Server(ldap_url, get_info=ALL, port=389, use_ssl=False)

        # 서비스 계정으로 바인드
        try:
                svc_conn = Connection(server, user=bind_dn, password=bind_pw, authentication=SIMPLE, auto_bind=True)
        except Exception as e:
                print(f"[ERROR] Service account bind failed: {e}")
                abort(500)

        # 유저 DN 검색
        search_filter = search_filter_template % username
        svc_conn.search(search_base=base_dn, search_filter=search_filter, attributes=ALL_ATTRIBUTES)

        if not svc_conn.entries:
                print(f"[ERROR] User {username} not found")
                abort(401)
                #return Response("unauthorized",status=401,headers={"WWW-Authenticate": f'Basic realm="{realm}"'})
        user_dn = svc_conn.entries[0].entry_dn
        print(f"[INFO] Found user DN: {user_dn}")

        # 유저 인증
        try:
                user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
                print(f"[INFO] User {username} authenticated OK")
                return True

        except Exception as e:
                #print(f"[ERROR] Invalid credentials for {user_dn}: {e}")
                return False
                #abort(401)
                #Response("unauthorized",status=401,headers={"WWW-Authenticate": f'Basic realm="{realm}"'})


def extract_username_from_token(token):
        try:
                payload = jwt.decode(token, key=None, options={"verify_signature": False})
                return payload.get("sub")
        except Exception:
                return None

if __name__ == "__main__":
        app.run(host="0.0.0.0", port=8001)
