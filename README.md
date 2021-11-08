### 과제
백만 개의 유해 사이트를 차단하라.

### 실행
```
syntax : 1m-block <site list file>
sample : 1m-block top-1m.txt
```

### 상세
* 이전 과제(netfilter-test)를 수행하고 나서 본 과제를 수행하도록 한다.

* zip 파일내의 1백만 개 사이트들을 유해사이트라고 간주하고 HTTP Reqeust에서 "Host: " 뒤의 Host 값을 알아 내서 백만 개 리스트 안에 존재하는지 판별하는 로직을 구현한다.

* 백만 개의 사이트 리스트틑 다음 zip 파일을 참고한다. 링크를 복사해서 다른 창에서 다운받을 수 있다. http://s3.amazonaws.com/alexa-static/top-1m.csv.zip 

* 로직의 구현은 메모리 및 검색 속도에 중점을 주도록 한다(프로그램을 돌려 놓고 실제로 인터넷 서핑 속도가 체감될 정도로 느려지면 안됨. 방법은 여러가지가 있을 수 있는데, 가장 쉽게할 수 있는 것이 sequential search이겠지만 이는 백만 개를 순차적으로 비교하는 로직이라서 검색 속도가 느려지게 됨. 어떠한 방법을 사용하든지 속도를 개선해 보고 가능하다면 메모리의 사용도 줄일 수 있는 다양한 방법을 고민해 볼 것).

* top-1m.csv.zip 파일을 풀면 csv 파일이 있는데 파일 포맷은 본인 프로그램에 맞게 수정을 해도 무방하다.

### 기타
* git에는 소스 코드(h, c, cpp)만 올리지 말고 프로젝트 파일(Makefile 혹은 *.pro)도 같이 올릴 것.
