# Simple tun/tap program

## About The Project
This program implement the basic feature for username/password authentication program, such as:
- User login verify

## Compile
```
$ make
```

## Usage
- Server side
```
[server]$ ./SimpleTunProgram -i tun13 -s
```
> The username/passowrd info have been stored in the [config](ServerConfig.txt) file
- Client side
```
[client]$ ./SimpleTunProgram -i tun0 -c <remote-server-ip>
```
> **tun13** and **tun0** must be replaced with the names of the actual tun interfaces used on the computers.

The server will ask client to log in (enter username and password), after receiving the client's username and password, the server will reponse the authentication result.


### 2022/07/28
Release 1st version.

#### New features:
- Support username/password authentication
    - Default config
        - Username : Andy
        - Password : Test1234

## Reference
This program is a modification of [gregnietsky](https://github.com/gregnietsky/simpletun)'s work.
