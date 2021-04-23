Program je napsaný v jazyce c#.
Pro jeho správnou funkčnost je potřeba knihovna libcap
Přeložení lze provést příkazem make nebo make all, úklid se provede příkazem make clean
Projekt lze spustit v kořenovém adresáři pomocí příkazu ./ipk-sniffer [-n počet paketů] [-i zařízení] [ -tcp nebo -t ] [ -udp nebo -u] [-p číslo portu]
Je zde volitelny argument -ipv6 (neni v zadani) vypisuje pouze ipv6 pakety
Program lze spustit bez argumentů a vypíše seznam zařízení.
Jinak se program musí spustit s administrátorskými právy.


