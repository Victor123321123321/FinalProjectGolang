���� ������ ���������� ������


������������� �����������. ����� 2

�����: ������ �������
t.me/VictorKopytov


� ������� �����������:

1. ��������� ����������� ������������. �������� ���� (����������� �����������). ���� ������������� ����� ���������� �������� ��� ������, ������ � ��������� ����������� ������������.
2. �������� ��������� ���������� �� ������ � SQLite. ������ ������� �������� ���������� ������������.
3. ����������� �������� ������� ���������� �������.
4. ����������� �������� ������� ��������������� �������.


���������� �� ������������:

1. ������� ���� orchestrator.go � ����� ���������� Visual Studio Code.
2. ��������� ���� orchestrator.go � ��������� Visual Studio Code ��������: go run orchestrator.go.
3. ��� ����������� ������������ �� ����� � �������� ������ �������� ���������� ������ ������ � �������: http://127.0.0.1:8080/register?username=VictorKopytov&password=qwerty123,
��� �������� username �������� �� ��� ������������, �������� password � ������.
4. ��� ����������� ������������ �� ����� � �������� ������ �������� ���������� ������ ������ � �������:
http://127.0.0.1:8080/login?username=VictorKopytov&password=qwerty123,
��� �������� username �������� �� ��� ������������, �������� password � ������.
����� ����������� � ���� �������� ����������� ����� (�������: {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls"}), ������� ���������� ��������� ��� ����������� �������������� � ������.
5. ��� ��������� ������� ���������� �������������� ��������, � �������� ������ �������� ���������� ������ ������ � �������: 
127.0.0.1:8080/settime?time+=10&time-=10&time*=10&time/=10&time_limit=60&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls
��� �������� time+ �������� �� ����� ���������� �������� ��������;
�������� time- �������� �� ����� ���������� �������� ���������;
�������� time* �������� �� ����� ���������� �������� ���������;
�������� time/ �������� �� ����� ���������� �������� �������;
�������� time_limit �������� �� ����� ������� �� ���������� ����� ��������������� ���������. ������� ��������� ���� ���������� � 1 ���;
�������� token  - ����� ����������� �����.
6. ��� �������� ��������������� ��������� � �������� ������ �������� ���������� ������ ������ � �������:
127.0.0.1:8080/add?expression=(1+3)*5-2*7&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls
��� �������� expression �������� �� ���������� ��������������� ���������
��������! ���� ��������� expression ��������������, ������, ��� ��������;
�������� token  - ����� ����������� �����.
�� ����������� �������� ����������� ����������: �Expression added by user� ����������, ��� ��������� ���������� �� ����������.
7. ��� ��������� �������� �� ������� ��������� � ���� ������ � �����������, � �������� ������ �������� ���������� ������ ������ � �������:
127.0.0.1:8080/list?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTM2OTc4NTcsImlhdCI6MTcxMzY5NzY3NywibmJmIjoxNzEzNjk3Njc3LCJ1c2VybmFtZSI6IjUifQ.DhT7MBRs0axGCELC2SdWKXCP7EL8ZeUH-WifXfN6sls,
��� �������� token  - ����� ����������� �����.


� ����� LookMe.mkv ��������� ���������������.
