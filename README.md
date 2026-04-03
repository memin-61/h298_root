# ZTE H298A Root Aracı
  [ENGLISH](https://github.com/memin-61/h298_root/blob/master/README_eng.md)
## Ne işe yarar?

Araç modemideki TR069 protokolünü kullanarak root ve shell kullanıcılarını etkinleştirir.

Bilgisayarda DHCP server çalıştırarak modemin IP alması sağlanır. CWMP sürecinde gerekli parametrelerin olup olmadığı sorgulanıp modemde varsa uygulanır. En sonunda bilgisayardaki internet ayarları varsayılan ayarlara geri döndürülür.

## Gereklilikler

- Npcap
- Python
- scapy

scapy paketini bu komut ile indirin:

```
pip install scapy
```

## Ön hazırlık

Modemi WAN portu üzerinden bilgisayara bağlayın.

## Kullanım

```
python h298a.py
```

`-p/--password` ile kendi şifrenizi girebilirsiniz.

Çalıştırdıktan sonra Ethernet adapörünüzü seçin ve ilerleyin.

İşlem tamamlandığında belirtilen şifre ile giriş yapabilirsiniz. Örnek:

```
Device successfully rooted
Username: root
Password: <şifreniz>
Enable SSH under Easy Menu -> Local Access -> SSH Port
```

Ayrıca SSH ile modeme bağlanmak isterseniz Kolay Menü - Yerel Erişim altında SSH portunu açarak erişebilirsiniz.

**Opsiyonel:**

Modem varsayılan olarak yetkileri kısıtlı SSH verir, bunu aşmak için SSH üzerinden aşağıda bulunan iki komudu girebilirsiniz:

```
sendcmd 1 DB set SSHCfg 0 SSH_Level 1
sendcmd 1 DB set SSHCfg 0 SSH_ProcType 0
```

## Şifre Formatı

- Minimum 8 karakter
- Minimum 1 rakam
- `pass`, `password`, `root`, `admin` gibi ifadeler kabul edilmiyor

## Not ve Uyarı

- Bu araç yalnızca H298A V1.0 içindir.
- Bu aracın kullanımından doğabilecek sorunların tüm sorumluluğu kullanıcıya aittir.
