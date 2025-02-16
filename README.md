# Auth AAA
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org)
[![Home Assistant](https://img.shields.io/badge/home_assistant-41BDF5.svg?style=for-the-badge&logo=home-assistant&logoColor=white)](https://www.home-assistant.io)
[![HACS](https://img.shields.io/badge/hacs-python_scripts-41BDF5.svg?style=for-the-badge)](https://hacs.xyz/docs/use/repositories/type/python_script/)
[![Release](https://img.shields.io/github/release/Losenmann/hacs-auth-aaa/all.svg?style=for-the-badge)](https://github.com/Losenmann/hacs-auth-aaa/releases)
[![Maintainer](https://img.shields.io/badge/maintainer-@losenmann-FF6E00?style=for-the-badge)](https://github.com/Losenmann)
[![Donate](https://img.shields.io/badge/donate-yoomoney-8B3FFD.svg?style=for-the-badge)](https://yoomoney.ru/to/410015216730856)

Python script for Home Assistant adding authentication via RADIUS or LDAP\
The project is based on the library [pyrad](https://github.com/pyradius/pyrad.git)

## Overview
The script is designed to authenticate users in Home Assistant via a RADIUS or LDAP. This allows you to centrally manage user access.<br>
The script supports 2 launch modes: [auth_providers](#usage-in-auth_provider-mode) and [CLI](#usage-in-cli-mode).

## Install
[![](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=losenmann&repository=hacs-auth-aaa&category=python_script)

- **Method 1.** [HACS](https://hacs.xyz) > Python Script > Add > Auth AAA > Install

- **Method 2.** Copy the manually  `auth-aaa.py` from [latest release](https://github.com/losenmann/iptv-toolkit/releases/latest/download/auth-aaa.py) to path `/config/python_scripts`
    ```sh
    wget -LP /config/python_scripts "https://github.com/losenmann/iptv-toolkit/releases/latest/download/auth-aaa.py"`
    ```

## Usage in auth_provider mode
### Setupe
#### **Home Assistant**
1. Set connection parameters in the `secrets.yaml` file. Example data
   ```yaml
   auth_aaa_server: "server.example.com"
   auth_aaa_radius_secret: "homeassistant"
   auth_aaa_ldap_userdn: "uid={},ou=people,dc=example,dc=com"
   auth_aaa_ldap_basedn: "ou=people,dc=example,dc=com"
   auth_aaa_ldap_filter: "(uid={})"
   auth_aaa_ldap_attrib: ["givenName","memberof"]
   ```
> [!IMPORTANT]
> {} - is replaced by the username
2. In the `configuration.yaml` file add the configuration, the authentication order matters
   ```yaml
   homeassistant:
     auth_providers:
       - type: command_line
         command: '/usr/local/bin/python'
         args: ['/config/python_scripts/auth-aaa.py', '-m']
         meta: true
       - type: homeassistant
   ```
> [!NOTE]
> The `meta: true` directive is responsible for writing some variables to standard output to populate the user account created in Home Assistant with additional data. Removing the directive will disable authorization in Home Assistant using the script.

#### **IF USED RADIUS**
   1. Add data from the file [dictionary](./dictionary) to the RADIUS server's `dictionary` file
   2. Set the user's `Hass-Group` attribute to `system-users`

      | Attribute | Type | Value | Description |
      | :-- | :--: | :-----: | :---------- |
      | `Hass-Group` | string | `system-users` <br> `system-admin` | User group (Default `system-users`) |
      | `Hass-Local-Only` | byte | `0` <br> `1` | Local login only <br> (Defaults `0`) |
      | `Hass-Is-Active` | byte  | `0` <br> `1` | Activate user account <br> (Defaults `1`) |
> [!WARNING]
> For correct operation RADIUS Authorization , you must add to the [dictionary](./dictionary) in the RADIUS server dictionary file.
<details><summary>For owners device MikroTik</summary>

   1. Install `user-manager` package
      ```rsc
      /tool/fetch mode=https url=("https://download.mikrotik.com/routeros/".[/system/routerboard/get upgrade-firmware]."/user-manager-".[/system/routerboard/get upgrade-firmware]."-".[/system/resource/get architecture-name].".npk") output=file
      /system/reboot
       ```
   2. Setup a `user-manager`
      ```rsc
      /user-manager/attribute/add name="Hass-Group" vendor-id=812300 type-id=1 value-type=string
      /user-manager/attribute/add name="Hass-Local-Only" vendor-id=812300 type-id=2 value-type=hex
      /user-manager/attribute/add name="Hass-Is-Active" vendor-id=812300 type-id=3 value-type=hex
      /user-manager/user/add name="homeassistant-test" password="homeassistant" attributes="Hass-Group:system-users,Hass-Local-Only:0,Hass-Is-Active:1"
      /user-manager/router/add name="homeassistant-router" shared-secret="homeassistant" address="<your_subnet>"
      ```

</details>

#### **IF USED LDAP**

The LDAP server must support the `memberof` module. There should be an entry in the configuration: `olcModuleload: memberof.so`. In Alpine Linux, the module can be installed like this: `apk add openldap-overlay-memberof`

The structure of the LDAP tree should look like this:
```
cn=system-admin,cn=homeassistant,dc=example,dc=com
cn=system-users,cn=homeassistant,dc=example,dc=com
```

Users can be added to a parent group:
```
cn=homeassistant,dc=example,dc=com
```
In this case, members of the parent group will have rights `system-users`

Prospective users must have the following attributes:
- uid
- givenName
- memberof

If the `givenName` attribute is missing, then the login will be used as the username

## Usage in CLI mode
In CLI mode, you need to set execution permissions `chmod +x ./python_scripts/auth-aaa.py`<br>
Or run via Python `python ./python_scripts/auth-aaa.py`
> [!NOTE]
> RADIUS connection parameters can be configured in `secrets.yaml`, see point 1 of the chapter [Usage in auth_provider mode](#usage-in-auth_provider-mode)
```
./python_scripts/auth-aaa.py -U 'username' -P 'password' -S 'server.example.com' -s 'secret'
```

## Script arguments
| key  | secrets                  | type    | required | description |
| :--- | :----------------------: | :----:  | :------: | :---------- |
| `-h` | `none`                   | boolean | no       | Get help information |
| `-m` | `none`                   | boolean | no       | Enable meta to output credentials to stdout <br> (Defaults to False) |
| `-t` | `none`                   | string  | no       | Set type AAA `RADIUS` or `LDAP` <br> (Defaults to `RADIUS`) |
| `-U` | `none`                   | string  | yes      | Username |
| `-P` | `none`                   | string  | yes      | Password |
| `-S` | `auth_aaa_server`        | string  | yes      | Server <br> (Defaults from `secrets.yaml`) |
| `-s` | `auth_aaa_radius_secret` | string  | yes      | RADIUS secret <br> (Defaults from `secrets.yaml`) |
| `-b` | `auth_aaa_ldap_basedn`   | string  | yes      | LDAP BASE DN <br> (Defaults from `secrets.yaml`) |
| `-u` | `auth_aaa_ldap_userdn`   | string  | yes      | LDAP USER DN <br> (Defaults from `secrets.yaml`) |
| `-f` | `auth_aaa_ldap_filter`   | string  | no       | LDAP FILTER <br> (Defaults from `secrets.yaml`) |
| `-a` | `auth_aaa_ldap_attrib`   | list    | no       | Get an array of attributes |
> [!IMPORTANT]
> When using keys, keys take precedence over values ​​from `secrets.yaml` and variables passed from Home Assistant

