# Symfonos1-Vulnhub-CEH
 
Kiểm tra check ip có thể dùng nmap or Angry IP Scanner để scan network
Ở đây mình dùng Angry IP Scanner để thấy máy vulnhub cho nhanh

### Angry IP Scanner 
<p align="left"><img src="/img/1.png" alt="Run"></p>

Sau khi đã có IP thì ta sẽ dùng nmap để scan dịch vụ của máy.
```bash
nmap -sV -sC -sN -p- 10.10.10.13
```