import re
import requests

url = "https://range.metaproblems.com/739c7a4b6b9d8d9281bb3a4c964e68ca/fastmath/"
response = requests.get(url, headers='', data='')
content = response.content
numbers = re.search(">([0-9\s\+\-]+)", str(content))
refresh = re.search('value="([0-9]+)', str(content))
numbers = numbers.group(1).split()
answer = int(numbers[0]) + int(numbers[2]) - int(numbers[4])
ansURL = f"https://range.metaproblems.com/739c7a4b6b9d8d9281bb3a4c964e68ca/fastmath/grade.php?refresh={refresh.group(1)}&answer={answer}"
submit = requests.get(ansURL, headers='', data='')
print(submit.content)