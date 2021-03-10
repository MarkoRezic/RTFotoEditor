require('dotenv').config();
const { DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    ORIGIN_FRONTEND,
    GMAIL_USER,
    GMAIL_PASSWORD,
    JWT_SECRET,
    SESSION_SECRET,
    CLOUDINARY_NAME,
    CLOUDINARY_API_KEY,
    CLOUDINARY_API_SECRET } = process.env;

const thisOrigin = 'https://studenti.sum.ba/RTFotoEditor';
const subdirectory = '/projekti/fsre_rwa/2020/g4/';

const express = require("express");
const app = express();
const mysql = require("mysql");
const cloudinary = require('cloudinary').v2;
cloudinary.config({
    cloud_name: CLOUDINARY_NAME,
    api_key: CLOUDINARY_API_KEY,
    api_secret: CLOUDINARY_API_SECRET
});

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cookie = require('cookie-signature');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

const bcrypt = require('bcrypt');
const saltRounds = 10;

const nodemailer = require('nodemailer');
var jwt = require('jsonwebtoken');

const options = {
    user: DB_USER,
    host: DB_HOST,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    // Whether or not to automatically check for and clear expired sessions:
    clearExpired: true,
    // How frequently expired sessions will be cleared; milliseconds:
    checkExpirationInterval: 30 * 1000,
    // The maximum age of a valid session; milliseconds:
    expiration: 120 * 60 * 1000,
};
const sessionStore = new MySQLStore(options);

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', ORIGIN_FRONTEND);
    //res.header('Access-Control-Allow-Origin', '*');
    res.header(
        'Access-Control-Allow-Headers',
        'Origin, Content-Type, Accept, Authorization, Set-Cookie'
    );

    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method == 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET, OPTIONS')
        return res.sendStatus(200);
    }
    next();
})

app.use('send-message', (req, res, next) => {
    res.header('Content-type', 'application/json; charset=UTF-8');
    next();
})

app.use(cookieParser());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.set('trust proxy', true);
app.use(session({
    key: 'userId',
    secret: SESSION_SECRET,
    store: sessionStore,
    proxy: true,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        maxAge: 120 * 60 * 1000, //minutes * seconds * miliseconds
        secure: true,
        httpOnly: true,
        sameSite: 'none'
    }
}));

const db = mysql.createPool({
    user: DB_USER,
    host: DB_HOST,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    charset: 'utf8mb4_unicode_ci',
});

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: GMAIL_USER,
        pass: GMAIL_PASSWORD,
    },
});

app.get('/', (req, res) => {
    return res.send('Server is running, origin: ' + ORIGIN_FRONTEND);
});

app.get('/favicon.ico', (req, res) => {
    return res.send('');
});

app.post('/register/user', (req, res) => {
    const { email, username, password, authority } = req.body;

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.log(err);
        }
        else {
            db.query('INSERT INTO users (email, username, password, authority, displayname, verified) VALUES (?,?,?,?,?,?)',
                [email, username.toLowerCase(), hash, authority, username, 'no'],
                (error, result) => {
                    if (error) {
                        console.log(error.message);
                    } else {
                        res.send('User registered!');
                        console.log('success');
                    }
                }
            );
        }
    })
});

app.post('/confirmation/send', (req, res) => {
    const { id, email } = req.body;
    db.query('SELECT id, verified FROM users WHERE id = ?', [id],
        (error, result) => {
            if (error) {
                console.log(error);
                res.end();
            }
            else if (result[0].verified === 'verified') {
                res.send('user already verified');
            }
            else {
                jwt.sign(
                    {
                        id: id,
                    },
                    JWT_SECRET,
                    {
                        expiresIn: '1d',
                    },
                    (err, emailToken) => {
                        if (err) {
                            console.log(err);
                            res.send('Nodemailer error');
                        }
                        else {
                            const url = thisOrigin + '/confirmation/' + emailToken;

                            transporter.sendMail({
                                to: email,
                                subject: 'Verify Email for RT Foto Editor',
                                html: '<div style="width: 400px;text-align: center;font-weight: bold;background-color: aliceblue;min-height: 150px;padding: 20px;border: 4px solid lightsteelblue;border-radius: 10px;font-size: 18px;">Please click this button to verify your email: <a href="' + url + '" style=' + '"font-family: Arial, Helvetica, sans-serif;font-size: 25px;display: block;border-radius: 7px;border: 4px solid lightskyblue;background-color: steelblue;color: lightblue;padding: 2px 12px;cursor: pointer;text-decoration: none;font-weight: bold;text-align: center;width: 180px;height: 40px;margin: auto;margin-top: 40px;' + '">Verify</a>',
                            });

                            res.send('Check your email');
                        }
                    },
                );
            }
        }
    );
});

app.use('/confirmation/:token', (req, res) => {
    jwt.verify(req.params.token, JWT_SECRET,
        (error, decoded) => {
            if (error) res.send('An error occurred during verification, your token is invalid or expired.')
            else {
                db.query('UPDATE users SET verified = ? WHERE id = ?', ['verified', decoded.id],
                    (error, result) => {
                        if (error) {
                            res.send('An error occurred during verification, ID = ' + decoded.id);
                        }
                        else {
                            console.log('Verification successful');
                            if (req.session.userInfo) {
                                req.session.userInfo.verified = 'verified';
                            }
                            if (req.get('Cookie')) {
                                //console.log(req.get('Cookie'));
                                var RTCookie = req.get('Cookie').split('; ').filter((c) => {
                                    return c.startsWith('userId=')
                                })
                                //console.log(req.get('Cookie').split('; '));
                                //console.log(RTCookie);
                                var sessionID = RTCookie.length !== 0 ? decodeURIComponent(RTCookie[0].slice(11)).replace(/"+/g, '') : decodeURIComponent(req.get('Cookie').slice(11)).replace(/"+/g, '');
                                //console.log('DECODED: ' + cookie.unsign(sessionID, SESSION_SECRET));
                                if (cookie.unsign(sessionID, SESSION_SECRET) !== false) {
                                    sessionID = cookie.unsign(sessionID, SESSION_SECRET);
                                    db.query("SELECT * FROM sessions WHERE session_id = ?",
                                        [sessionID],
                                        (error, result) => {
                                            if (error) {
                                                console.log(error.message);
                                                res.redirect('https://' + ORIGIN_FRONTEND + subdirectory);
                                            }
                                            else if (result.length > 0) {
                                                let cookie = JSON.parse(result[0].data);
                                                cookie['userInfo']['loaded'] = true;
                                                cookie['userInfo']['verified'] = 'verified';
                                                console.log('session found' + cookie['userInfo']);
                                                db.query("UPDATE sessions SET data=? WHERE session_id=?",
                                                    [JSON.stringify(cookie), sessionID],
                                                    (error, result) => {
                                                        if (error) {
                                                            console.log(error)
                                                            res.redirect('https://' + ORIGIN_FRONTEND + subdirectory);

                                                        }
                                                        else {
                                                            console.log('session updated');
                                                            res.redirect('https://' + ORIGIN_FRONTEND + subdirectory);
                                                        }
                                                    })
                                            }
                                            else {
                                                console.log('session not found');
                                                res.send(userInfo);
                                            }
                                        })
                                }
                                else {
                                    console.log('no current session');
                                    res.redirect('https://' + ORIGIN_FRONTEND + subdirectory);
                                }
                            }
                            else {
                                console.log('no current session');
                                res.redirect('https://' + ORIGIN_FRONTEND + subdirectory);
                            }
                        }
                    }
                );
            }
        });
});

app.get('/messages/:id', (req, res) => {
    const userID = req.params.id;
    db.query('SELECT id, sender_id, reciever_id, date, text, opened, time FROM messages WHERE reciever_id = ?', [userID],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
})

app.get('/messages-sent/:id', (req, res) => {
    const userID = req.params.id;
    db.query('SELECT id, sender_id, reciever_id, date, text, opened, time FROM messages WHERE sender_id = ?', [userID],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
})

app.delete("/remove-message", (req, res) => {
    const { message_id } = req.body;
    console.log('deleting message id=' + message_id);
    db.query('DELETE FROM messages WHERE id = ?',
        [message_id],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                res.send("message deleted, id = " + message_id);
            }
        }
    );
})

app.delete("/remove-messages-recieved", (req, res) => {
    const { reciever_id } = req.body;
    console.log('deleting recieved messages user id=' + reciever_id);
    db.query('DELETE FROM messages WHERE reciever_id = ?',
        [reciever_id],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                res.send("recieved messages deleted, user id = " + reciever_id);
            }
        }
    );
})

app.delete("/remove-messages-sent", (req, res) => {
    const { sender_id } = req.body;
    console.log('deleting sent messages user id=' + sender_id);
    db.query('DELETE FROM messages WHERE sender_id = ?',
        [sender_id],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                res.send("sent messages deleted, user id = " + sender_id);
            }
        }
    );
})

app.post('/send-message', (req, res) => {
    const { sender_id, reciever_id, text } = req.body;
    var time = new Date();
    var time = ('00' + time.getHours()).slice(-2) + ':' +
        ('00' + time.getMinutes()).slice(-2);
    db.query('INSERT INTO messages (sender_id, reciever_id, date, text, opened, time) VALUES (?,?,CURRENT_TIMESTAMP(),?,?,?)',
        [sender_id, reciever_id, text, 0, time],
        (error, result) => {
            if (error) {
                console.log(error.message);
                res.send(error);
            } else {
                res.send('message sent');
            }
        }
    );
})

app.post('/image/upload/post', async (req, res) => {
    try {
        var { data, userID, description, view } = req.body;
        console.log('user id: ' + userID);
        console.log('description: ' + description);
        console.log('view: ' + view);
        if (!userID) res.send('user not logged in');
        else {
            var time = new Date();
            var time = ('00' + time.getHours()).slice(-2) + ':' +
                ('00' + time.getMinutes()).slice(-2);
            const uploadedResponse = await cloudinary.uploader.upload(data, {
                upload_preset: 'posts'
            })
            console.log(uploadedResponse);
            db.query('INSERT INTO posts (poster_id, public_id, description, view, date, time) VALUES (?,?,?,?,CURRENT_TIMESTAMP(),?)',
                [userID, uploadedResponse.public_id, description, view.toLowerCase(), time],
                (error, result) => {
                    if (error) {
                        console.log(error.message);
                        res.send(error);
                    } else {
                        db.query('SELECT id FROM posts ORDER BY id DESC LIMIT 1',
                            (error, result) => {
                                if (error) {
                                    console.log('error');
                                }
                                else if (result) {
                                    console.log(result);
                                    res.send(result);
                                }
                                else res.send('no id');
                            }
                        );
                    }
                }
            );
        }
    } catch (error) {
        console.log(error);
        res.send('image upload error');
    }
});

app.post('/image/upload/profile', (req, res) => {
    try {
        var { data, userID } = req.body;
        console.log('user id: ' + userID);
        if (!userID) res.send('ID invalid');
        else {
            db.query('SELECT public_id FROM profile_images WHERE user_id=?',
                [userID],
                async (err, result) => {
                    try {
                        if (err) {
                            console.log(err);
                            res.send('An error occurred');
                        }
                        else if (result.length > 0) {
                            await cloudinary.uploader.destroy(result[0].public_id);
                            const uploadedResponse = await cloudinary.uploader.upload(data, {
                                upload_preset: 'profile_images'
                            })
                            console.log(uploadedResponse);
                            db.query('UPDATE profile_images SET public_id = ? WHERE user_id = ?',
                                [uploadedResponse.public_id, userID],
                                (error, result) => {
                                    if (error) {
                                        res.send(error);
                                    }
                                    else {
                                        res.send('profile image updated');
                                    }
                                }
                            );
                        }
                        else {
                            const uploadedResponse = await cloudinary.uploader.upload(data, {
                                upload_preset: 'profile_images'
                            })
                            console.log(uploadedResponse);
                            db.query('INSERT INTO profile_images (user_id, public_id) VALUES (?,?)',
                                [userID, uploadedResponse.public_id],
                                (error, result) => {
                                    if (error) {
                                        console.log(error.message);
                                        res.send(error);
                                    }
                                    else {
                                        res.send('profile image uploaded');
                                    }
                                }
                            );
                        }
                    } catch (error) {
                        console.log(error);
                        res.send('image upload error');
                    }
                })
        }
    } catch (error) {
        console.log(error);
        res.send('image upload error');
    }
});

app.get('/images/all/posts', async (req, res) => {
    const { resources } = await cloudinary.search
        .expression('folder:posts')
        .execute();

    const publicIds = resources.map((file) => file.public_id);
    res.send(publicIds);
});

app.get('/images/all/profile_images', async (req, res) => {

    db.query('SELECT * FROM profile_images',
        (error, result) => {
            if (error) {
                console.log('error');
                res.send('an error occurred');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/posts/public', (req, res) => {

    db.query('SELECT posts.id, users.displayname, posts.public_id FROM posts INNER JOIN users ON users.id = posts.poster_id WHERE posts.view = ?', ['public'],
        (error, result) => {
            if (error) {
                console.log('error');
                res.send('an error occurred');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/posts/:id', (req, res) => {

    db.query('SELECT posts.id, posts.poster_id, users.displayname, posts.public_id, posts.description, posts.view, posts.date, posts.time FROM posts INNER JOIN users ON users.id = posts.poster_id WHERE posts.id = ?', [req.params.id],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.post('/post/like/:id', (req, res) => {
    var { userID, type } = req.body;
    console.log(req.body);

    db.query('DELETE FROM likes WHERE post_id=? AND user_id=?',
        [req.params.id, userID],
        (error, result) => {
            if (error) {
                console.log('error');
            } else if (type !== '') {
                db.query('INSERT INTO likes (post_id, user_id, type) VALUES (?,?,?)',
                    [req.params.id, userID, type],
                    (error, result) => {
                        if (error) {
                            console.log('error');
                        } else {
                            res.send(type === 'like' ? 'post liked' : 'post disliked');
                        }
                    }
                );
            }
            else {
                res.send('like reset');
            }
        }
    );

});

app.get('/post/likes/:id', (req, res) => {

    db.query('SELECT likes.id, likes.post_id, likes.user_id, likes.type FROM likes INNER JOIN posts ON likes.post_id = posts.id WHERE type = ? AND likes.post_id=?', ['like', req.params.id],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/posts-likesCount', (req, res) => {

    db.query('SELECT likes.post_id, COUNT(*) AS total FROM likes WHERE type = ? GROUP BY likes.post_id', ['like'],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/posts-dislikesCount', (req, res) => {

    db.query('SELECT likes.post_id, COUNT(*) AS total FROM likes WHERE type = ? GROUP BY likes.post_id', ['dislike'],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/post/dislikes/:id', (req, res) => {

    db.query('SELECT likes.id, likes.post_id, likes.user_id, likes.type FROM likes INNER JOIN posts ON likes.post_id = posts.id WHERE type = ? AND likes.post_id=?', ['dislike', req.params.id],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/profile_images/:userID', (req, res) => {

    db.query('SELECT id, public_id FROM profile_images WHERE user_id = ?', [req.params.userID],
        (error, result) => {
            if (error) {
                console.log('error');
            }
            else {
                res.send(result);
            }
        }
    );
});

app.get('/users', (req, res) => {

    db.query('SELECT email, username, authority, id, displayname, verified FROM users',
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get('/users/:userID', (req, res) => {

    db.query('SELECT email, username, authority, id, displayname, verified FROM users WHERE id=?', [req.params.userID],
        (error, result) => {
            if (error) {
                console.log('error');
            } else {
                res.send(result);
            }
        }
    );
});

app.get("/userAuthentication", (req, res) => {
    if (req.get('Cookie') && cookie.unsign(decodeURIComponent(req.get('Cookie').slice(11)).replace(/"+/g, ''), SESSION_SECRET) !== false) res.send({ authenticated: true });
    else res.send({ authenticated: false });
})

app.post('/loginStatus', (req, res) => {

    var userInfo = {
        loggedIn: false,
        loaded: true,
        username: null,
        displayname: null,
        email: null,
        id: null,
        authority: 'guest',
        verified: 'guest'
    };

    if (req.get('Cookie')) {
        //console.log(req.get('Cookie'));
        var RTCookie = req.get('Cookie').split('; ').filter((c) => {
            return c.startsWith('userId=')
        })
        //console.log(req.get('Cookie').split('; '));
        //console.log(RTCookie);
        var sessionID = RTCookie.length !== 0 ? decodeURIComponent(RTCookie[0].slice(11)).replace(/"+/g, '') : decodeURIComponent(req.get('Cookie').slice(11)).replace(/"+/g, '');
        //console.log('DECODED: ' + cookie.unsign(sessionID, SESSION_SECRET));
        if (cookie.unsign(sessionID, SESSION_SECRET) !== false) {
            sessionID = cookie.unsign(sessionID, SESSION_SECRET);
            db.query("SELECT * FROM sessions WHERE session_id = ?",
                [sessionID],
                (error, result) => {
                    if (error) {
                        console.log(error.message);
                        res.send(userInfo);
                    }
                    else if (result.length > 0) {
                        let cookie = JSON.parse(result[0].data);
                        userInfo = cookie['userInfo'];
                        userInfo['loaded'] = true;
                        console.log('session found' + cookie['userInfo']);
                        res.send(userInfo);
                    }
                    else {
                        console.log('session not found');
                        res.send(userInfo);
                    }
                })
        }
        else {
            console.log('no current session');
            res.send(userInfo);
        }
    }
    else {
        console.log('no current session');
        res.send(userInfo);
    }
})

app.post('/login', (req, res) => {

    const { username, password } = req.body;
    var userInfo = {
        loggedIn: false,
        loaded: true,
        username: null,
        displayname: null,
        email: null,
        id: null,
        authority: 'guest',
        verified: 'guest'
    };

    if (username && password) db.query('SELECT * FROM users WHERE username = ?',
        [username],
        (error, result) => {
            if (error) {
                console.log(error.message);
                res.status(500).send(error.message);
            }
            else if (result.length > 0) {
                console.log('username found');

                bcrypt.compare(password, result[0].password, (error, response) => {
                    if (response) {
                        userInfo = {
                            loggedIn: true,
                            loaded: true,
                            username: result[0].username,
                            displayname: result[0].displayname,
                            email: result[0].email,
                            id: result[0].id,
                            authority: result[0].authority,
                            verified: result[0].verified
                        };

                        req.session.userInfo = userInfo;
                        res.header('Set-Cookie', 'userId=rtrt' + cookie.sign('' + req.sessionID, SESSION_SECRET) + '; SameSite=none; Secure');

                        console.log('user logged in');
                        res.send(userInfo);
                    }
                    else {
                        userInfo = {
                            loggedIn: false,
                            loaded: true,
                            username: result[0].username,
                            displayname: null,
                            email: null,
                            id: null,
                            authority: 'guest',
                            verified: 'guest'
                        };
                        console.log('wrong password');
                        res.send(userInfo);
                    }
                })

            }
            else {
                console.log('username not found');
                res.send(userInfo);
            }
        }
    );
    else res.send(userInfo);
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.header('Set-Cookie', 'userId=rtrt; ');
    res.send({
        loggedIn: false,
        loaded: true,
        username: null,
        displayname: null,
        email: null,
        id: null,
        authority: 'guest',
        verified: 'guest'
    });
});

app.delete("/remove-user", (req, res) => {
    const { userID } = req.body;
    console.log('deleting user id=' + userID);
    db.query('DELETE FROM users WHERE id = ?',
        [userID],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                res.send("user deleted, id = " + userID);
            }
        }
    );
})

app.put("/update-username", (req, res) => {
    const { username, userID } = req.body.data;
    console.log('updating username user id=' + userID);
    db.query('UPDATE users SET username = ?, displayname = ? WHERE id = ?',
        [username.toLowerCase(), username, userID],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                if (req.session.userInfo) {
                    req.session.userInfo.username = username.toLowerCase();
                    req.session.userInfo.displayname = username;
                }
                res.send('username changed to ' + username + ', id = ' + userID);
            }
        }
    );
})

app.put("/update-password", (req, res) => {
    const { password, userID } = req.body.data;
    console.log('updating password user id=' + userID);

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.log(err);
        }
        else {
            db.query('UPDATE users SET password = ? WHERE id = ?',
                [hash, userID],
                (error, result) => {
                    if (error) {
                        res.send(error);
                    }
                    else {
                        res.send('password changed, id = ' + userID);
                    }
                }
            );
        }
    })


})

app.put("/update-role", (req, res) => {
    const { userID, newRole } = req.body.data;
    console.log('updating role to ' + newRole + ', user id =' + userID);

    db.query('UPDATE users SET authority = ? WHERE id = ?',
        [newRole, userID],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                if (req.session.userInfo) {
                    req.session.userInfo.authority = newRole;
                }
                res.send('role changed to ' + newRole + ', id = ' + userID);
            }
        }
    );
})

app.put("/open-messages", (req, res) => {
    const { sender_id, reciever_id } = req.body.data;

    db.query('UPDATE messages SET opened = ? WHERE sender_id = ? AND reciever_id = ?',
        [1, sender_id, reciever_id],
        (error, result) => {
            if (error) {
                res.send(error);
            }
            else {
                res.send('opened messages from id=' + sender_id);
            }
        }
    );
})


app.listen(process.env.PORT || 3001, () => {
    console.log("server running");
});