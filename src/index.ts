import express from 'express';
import { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

type DataType = {
    id: number;
    FirstName: string;
    SurName: string;
    LastName: string;
    berthday: string;
    email: string;
    password: string;
    readonly role: string;
    status: boolean;
};
const app = express();
const PORT = process.env.PORT || 3000;
const urlencodedParser = express.urlencoded({ extended: false });
const pool = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    port: 3306,
    database: 'test',
    password: '123test',
});
app.set('view engine', 'hbs');
pool.connect(function (err) {
    if (err) {
        return console.error('Ошибка: ' + err.message);
    } else {
        console.log('Подключение к серверу MySQL успешно установлено');
    }
});
pool.query('SELECT * FROM user ', function (err, data) {
    if (err instanceof Error) {
        console.log(err);
    } else {
        console.log(data);
    }
});
const id = [8];
pool.query('SELECT * FROM user WHERE id=?', id, function (err, data) {
    if (err instanceof Error) {
        console.log(err);
    } else {
        console.log(data);
    }
});

pool.query('DELETE FROM `user` WHERE `id` = ?', [id], function (err, data) {
    if (err instanceof Error) {
        console.log(err);
    } else {
        console.log(data);
    }
});
pool.query('SELECT * FROM user', function (err, results, fields) {
    console.log(err);
    console.log(`result`, results);
    console.log(fields);
});

//secret jwt
const SECRET = 'secret';
//default users

const users: DataType[] = [
    {
        id: 0,
        FirstName: 'Сидоров',
        SurName: 'Коля',
        LastName: 'Александрович',
        berthday: '13.06.89',
        email: 'sidor@mail.ru',
        password: '123',
        role: 'user',
        status: true,
    },
];

//All users
app.get('/users', function (req: Request, res: Response) {
    pool.query('SELECT * FROM user', function (err, data) {
        if (err) {
            res.status(500).send(err);
        } else {
            res.status(200).json(data);
        }
    });
});

//search id

app.get('/users/:id', urlencodedParser, function (req: Request, res: Response) {
    const id = req.params.id;
    const sql = 'SELECT * FROM `user` WHERE `id` = ?';
    pool.query(sql, [id], function (err, data) {
        if (err) {
            return res
                .status(500)
                .json({ message: 'Пользователь по идентификатору не найден' });
        } else {
            return res.status(200).json(data);
        }
    });
});
// Create a new user
app.post('/users/register', function (req: Request, res: Response) {
    const idUser = users.map((item, index) => (item.id = index + 1));
    const id = +idUser.join('');
    const FirstName = req.body.FirstName;
    const SurName = req.body.SurName;
    const LastName = req.body.LastName;
    const berthday = req.body.berthday;
    const email = req.body.email;
    const password = req.body.password;
    const role = req.body.role;
    const status = req.body.status;

    if (!FirstName || !SurName || LastName || berthday || !email || !password)
        return res.status(400).json({ message: 'Нет данных' });
    const salt = bcrypt.genSaltSync(10);
    const hashe = bcrypt.hashSync(password, salt);
    users.push({
        id,
        FirstName,
        SurName,
        LastName,
        berthday,
        email,
        password: hashe,
        role,
        status,
    });
    pool.query(
        'INSERT INTO `user` ( `FirstName`, `SurName`, `LastName`, `berthday`, `email`, `password`,`role`, `status`) VALUES (?,?,?,?,?,?,?,?)',

        [FirstName, SurName, LastName, berthday, email, password, role, status],
        function (err) {
            if (err) {
                res.status(500).send(err);
            } else {
                res.status(201).send({
                    FirstName,
                    SurName,
                    LastName,
                    berthday,
                    email,
                    password,
                    role,
                    status,
                });
            }
        },
    );
});

//login and autentification
app.post('/users/login', function (req: Request, res: Response) {
    const { email, password } = req.body;

    if (!email || !password)
        return res.status(401).json({ message: 'Введите почту и пароль' });
    const sql = 'SELECT * FROM `user` WHERE `email` = ? AND `password` =?';
    const user = users.find((item) => item.password === password);
    pool.query(sql, [email, password], function (err, result) {
        if (err) {
            return res.status(404).json({
                message: 'Пользователь с такой почтой и паролем не найден',
            });
        } else {
            if (user) {
                const isPasswordValid = bcrypt.compareSync(
                    password,
                    user.password,
                );
                if (!isPasswordValid) {
                    return res.status(401).json({
                        message: 'Пароль не валиден',
                    });
                }
                const token = jwt.sign(
                    {
                        id: user.id,
                        email: user.email,
                    },
                    SECRET,

                    {
                        expiresIn: '1h',
                    },
                );
                res.status(200).json({ message: 'Успешно', token });
            } else {
                return res
                    .status(404)
                    .json({ message: 'Пользователь не найден' });
            }
        }
    });
});

//Update User
app.put('/users/:id', function (req: Request, res: Response) {
    const { id } = req.params;
    const { FirstName, SurName, LastName, email, berthday, password } =
        req.body;
    const sql =
        'UPDATE `user` SET `FirstName` =?, `LastName` = ?, `email` = ?, `berthday` = ?,  `password` = ? WHERE `id` = ?';
    pool.query(
        sql,
        [FirstName, SurName, LastName, email, berthday, password, id],
        (err, result) => {
            if (err) return res.status(500).send(err);
            res.status(200).send({
                id,
                FirstName,
                SurName,
                LastName,
                email,
                berthday,
                password,
            });
        },
    );
});

function auth(roles: string[]) {
    return function (req: Request, res: Response, next: NextFunction) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                message: 'Токен не найден',
            });
        }

        jwt.verify(token, SECRET, function (err, userRole) {
            userRole = users.map((item) => item.role).join('');
            if (err) {
                return res.status(403).json({
                    message: 'Токен не валиден',
                });
            }
            if (!roles.includes(userRole)) {
                res.status(403).json({
                    message: 'Статус -админ',
                });
            } else {
                res.status(201).json({
                    message: 'Статус -пользователь',
                });
            }
            req.body = userRole;
            next();
        });
    };
}
//get role
app.get(
    '/users/profile',
    auth(['user']),
    function (req: Request, res: Response) {
        res.status(200).json({
            message: `Добро пожаловать -${req.body.userRole}`,
        });
    },
);
//Delete user
app.delete('/delete/:id', function (req: Request, res: Response) {
    const id = Number(req.params.id);
    pool.query('DELETE FROM `user` WHERE `id` = ?', [id], function (err) {
        if (err) {
            res.status(500).json({ err: 'Пользователь не заблокирован' });
        } else {
            res.status(200).json({ message: 'Пользователь  заблокирован' });
        }
    });
});
app.listen(PORT, function () {
    console.log(`Server listen to port ${PORT}`);
});
