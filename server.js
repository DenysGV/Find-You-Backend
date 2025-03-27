import dotenv from 'dotenv';
import express from 'express';
import pkg from 'pg';
import cors from 'cors';
import svgCaptcha from 'svg-captcha';
import bcrypt from 'bcrypt';
import authMiddleware from './authMiddleware.js';
import jwt from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer'
import multer from 'multer';
import { TextDecoder } from 'util';
import iconv from 'iconv-lite'
import xss from 'xss';

dotenv.config();

const upload = multer({ dest: 'filebase/' });

const storage = multer.memoryStorage();
const uploadPhoto = multer({ storage: storage });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Настройка соединения с PostgreSQL
const { Pool } = pkg;  // Используем default импорт из pg для получения Pool

const pool = new Pool({
   user: process.env.DB_USER,
   host: process.env.DB_HOST,
   database: process.env.DB_NAME,
   password: process.env.DB_PASSWORD,
   port: process.env.DB_PORT,
   charset: "utf8",
});

export default pool;


app.use(cors());

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'fileBase')));
app.use((req, res, next) => {
   // Рекурсивно очищаем все поля в запросах
   function sanitizeObject(obj) {
      for (let key in obj) {
         if (typeof obj[key] === 'object') {
            sanitizeObject(obj[key]); // Рекурсивная очистка вложенных объектов
         } else if (typeof obj[key] === 'string') {
            obj[key] = xss(obj[key]); // Очистка строк
         }
      }
   }

   // Если есть данные в теле запроса, очищаем их
   if (req.body) {
      sanitizeObject(req.body);
   }

   // Если есть параметры в URL, очищаем их
   if (req.query) {
      sanitizeObject(req.query);
   }

   // Если есть параметры в URL-пути, очищаем их
   if (req.params) {
      sanitizeObject(req.params);
   }

   next();
});


function buildCommentTree(comments) {
   const commentMap = new Map();

   // Заполняем карту комментариев
   comments.forEach(comment => {
      comment.children = [];
      commentMap.set(comment.id, comment);
   });

   const tree = [];

   comments.forEach(comment => {
      if (comment.parent_id !== null) {
         const parent = commentMap.get(comment.parent_id);
         if (parent) {
            parent.children.push(comment);
         }
      } else {
         tree.push(comment);
      }
   });

   return tree;
}

function decodeFile(buffer) {
   // Пробуем сначала с UTF-8
   try {
      const decoder = new TextDecoder('utf-8', { fatal: true }); // 'fatal' выбрасывает ошибку при неправильной кодировке
      return decoder.decode(buffer);
   } catch (error) {
      // Если ошибка, пробуем с Windows-1251
      return iconv.decode(buffer, 'windows-1251');
   }
}

function parseTxtFile(filePath) {
   const buffer = fs.readFileSync(filePath);
   const fileContent = decodeFile(buffer);

   return new Promise((resolve, reject) => {
      if (!fileContent) {
         return reject(new Error('Файл пустой или не найден'));
      }

      // Регулярное выражение для извлечения всего аккаунта
      const readyAccounts = [];
      const accountPattern = /<title>(.*?)<\/title>[\s\S]*?<id>(.*?)<\/id>[\s\S]*?<dr>(.*?)<\/dr>[\s\S]*?<city>(.*?)<\/city>[\s\S]*?<skype>(.*?)<\/skype>[\s\S]*?<icq>(.*?)<\/icq>[\s\S]*?<fb>(.*?)<\/fb>[\s\S]*?<od>(.*?)<\/od>[\s\S]*?<insta>(.*?)<\/insta>[\s\S]*?<tw>(.*?)<\/tw>[\s\S]*?<girl>(.*?)<\/girl>[\s\S]*?<boy>(.*?)<\/boy>[\s\S]*?<email>(.*?)<\/email>[\s\S]*?<tg>(.*?)<\/tg>[\s\S]*?<tik>(.*?)<\/tik>[\s\S]*?<of>(.*?)<\/of>[\s\S]*?<tel>(.*?)<\/tel>[\s\S]*?<nvideo>(.*?)<\/nvideo>[\s\S]*?<tags>(.*?)<\/tags>[\s\S]*?<date>(.*?)<\/date>?/g;

      let match;
      while ((match = accountPattern.exec(fileContent)) !== null) {
         const dateValue = match[20]; // Значение даты из тега <date>
         let date_of_create;

         if (dateValue === undefined) {
            // Если тега <date> нет, устанавливаем текущую дату
            date_of_create = new Date().toISOString();
         } else if (dateValue.trim() === '') {
            // Если тег <date> пустой, устанавливаем null
            date_of_create = null;
         } else {
            // Если в теге <date> есть значение, используем его
            date_of_create = dateValue.trim();
         }

         const accountData = {
            title: match[1],
            id: match[2],
            dr: match[3],
            city: match[4],
            skype: match[5],
            icq: match[6],
            fb: match[7],
            od: match[8],
            insta: match[9],
            tw: match[10],
            girl: match[11],
            boy: match[12],
            email: match[13],
            tg: match[14],
            tik: match[15],
            of: match[16],
            tel: match[17],
            nvideo: match[18],
            tags: match[19],
            date_of_create, // Записываем значение для даты
         };

         // Если id присутствует, добавляем аккаунт в список
         if (accountData.id) {
            readyAccounts.push(accountData);
         }
      }

      // Если нет данных, возвращаем ошибку
      if (readyAccounts.length === 0) {
         return reject(new Error('Нет данных аккаунтов в файле'));
      }

      resolve(readyAccounts); // Возвращаем массив данных для всех аккаунтов
   });
}

app.get('/accounts', async (req, res) => {
   try {
      let { search, city_id, tag_id, date_range, page = 1, limit = 40 } = req.query;
      page = parseInt(page);
      limit = parseInt(limit);
      const offset = (page - 1) * limit;

      let query = `
         SELECT DISTINCT a.id, a.name, a."City_id", a.date_of_create, a.date_of_birth, a.identificator, a.photo, a.check_video 
         FROM accounts a
         LEFT JOIN tags_detail td ON a.id = td.account_id
         LEFT JOIN tags t ON td.tag_id = t.id
         LEFT JOIN city c ON a."City_id" = c.id
      `;

      let queryParams = [];
      let conditions = [];

      // Фильтр по ID города
      if (city_id) {
         conditions.push(`a."City_id" = $${queryParams.length + 1}`);
         queryParams.push(city_id);
      }

      // Фильтр по ID тега
      if (tag_id) {
         conditions.push(`t.id = $${queryParams.length + 1}`);
         queryParams.push(tag_id);
      }

      // Фильтр по текстовому поиску
      if (search && search.trim() !== "") {
         const searchQuery = `%${search.toLowerCase()}%`;

         // Фильтр по возрасту
         if (!isNaN(search)) {
            const age = parseInt(search);
            conditions.push(`DATE_PART('year', AGE(a.date_of_birth::DATE)) = $${queryParams.length + 1}`);
            queryParams.push(age);
         } else {
            conditions.push(`
               LOWER(a.name) LIKE LOWER($${queryParams.length + 1}) 
               OR LOWER(c.name_ru) LIKE LOWER($${queryParams.length + 1}) 
               OR LOWER(c.name_eu) LIKE LOWER($${queryParams.length + 1}) 
               OR LOWER(t.name_ru) LIKE LOWER($${queryParams.length + 1}) 
               OR LOWER(t.name_eu) LIKE LOWER($${queryParams.length + 1})
            `);
            queryParams.push(searchQuery);
         }
      }

      // Фильтр по диапазону дат
      if (date_range) {
         try {
            const dates = JSON.parse(date_range);
            const startDate = dates[0] ? dates[0] : null;
            const endDate = dates[1] ? dates[1] : null;

            if (startDate && endDate) {
               conditions.push(`a.date_of_create::DATE BETWEEN $${queryParams.length + 1} AND $${queryParams.length + 2}`);
               queryParams.push(startDate, endDate);
            } else if (startDate) {
               conditions.push(`a.date_of_create::DATE = $${queryParams.length + 1}::DATE`);
               queryParams.push(startDate);
            }
         } catch (error) {
            console.error("Invalid date_range format:", error);
            return res.status(400).json({ error: "Invalid date_range format. It should be a JSON array." });
         }
      }

      // Применяем фильтры, если есть условия
      if (conditions.length > 0) {
         query += " WHERE " + conditions.join(" AND ");
      }

      query += ` ORDER BY a.date_of_create DESC LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}`;
      queryParams.push(limit, offset);

      // Выполнение запроса
      const result = await pool.query(query, queryParams);
      let accounts = result.rows;

      // Проверяем фото
      for (let account of accounts) {
         if (!account.photo) {
            const userDir = path.join(__dirname, 'fileBase', account.identificator);

            try {
               if (fs.existsSync(userDir)) {
                  const files = fs.readdirSync(userDir).filter(file => /\.(jpg|jpeg|png|gif)$/i.test(file));
                  account.photo = files.length > 0 ? `/uploads/${account.identificator}/${files[0]}` : null;
               } else {
                  account.photo = null;
               }
            } catch (err) {
               console.error(`Ошибка при проверке фото для аккаунта ${account.identificator}:`, err);
               account.photo = null;
            }
         }
      }

      res.json(accounts);
   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.get('/account', async (req, res) => {
   try {
      const { id } = req.query;

      const userQuery = await pool.query("SELECT * FROM accounts WHERE Id = $1", [id]);
      if (userQuery.rows.length === 0) {
         return res.status(400).json({ message: "Пользователь не найден" });
      }
      const user = userQuery.rows[0];

      const cityQuery = await pool.query(`SELECT * FROM city WHERE id = $1`, [user.City_id]);
      const city = cityQuery.rows[0];

      const tagsQuery = await pool.query(`
         SELECT tags.id, tags.name_ru, tags.name_eu 
         FROM tags
         JOIN tags_detail ON tags.id = tags_detail.tag_id
         WHERE tags_detail.account_id = $1
      `, [id]);
      const tags = tagsQuery.rows;

      const socialsQuery = await pool.query(`
         SELECT socials.id, socials.type_social_id, socials.text, socials_type.name AS social_name
         FROM socials
         JOIN socials_type ON socials.type_social_id = socials_type.id
         JOIN socials_detail ON socials.id = socials_detail.socials_id
         WHERE socials_detail.account_id = $1
      `, [id]);
      const socials = socialsQuery.rows;

      const ratingQuery = await pool.query(`SELECT * FROM rating WHERE account_id = $1`, [id]);
      const rating = ratingQuery.rows;

      const commentsQuery = await pool.query(`
         SELECT comments.*, users.login AS author_nickname
         FROM comments
         JOIN users ON comments.user_id = users.id
         WHERE comments.account_id = $1
      `, [id]);
      const commentsTree = buildCommentTree(commentsQuery.rows);

      const userDetailsQuery = await pool.query(`SELECT * FROM users WHERE login = $1`, [user.login]);
      const userDetails = userDetailsQuery.rows[0];

      // 📂 Читаем файлы из папки fileBase/<id>
      const filesDirectory = path.join(__dirname, 'fileBase', user.identificator);
      let files = [];

      if (fs.existsSync(filesDirectory)) {
         files = fs.readdirSync(filesDirectory)
            .filter(file => file.endsWith('.jpg') || file.endsWith('.png') || file.endsWith('4')) // Добавляем MP4
            .map(file => `/uploads/${user.identificator}/${file}`);
      }

      // Собираем финальный объект
      const fullAccountInfo = {
         account: user,
         city: city,
         tags: tags,
         socials: socials,
         rating: rating,
         comments: commentsTree,
         userDetails: userDetails,
         files: files  // 📂 Добавляем файлы
      };

      res.json(fullAccountInfo);

   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.get('/cities', authMiddleware, async (req, res) => {
   try {
      const result = await pool.query(`
         SELECT 
            c.id AS City_ID, 
            c.name_ru AS City_Name, 
            COUNT(a.id) AS Account_Count
         FROM accounts a
         JOIN city c ON a."City_id" = c.id
         GROUP BY c.id, c.name_ru
         ORDER BY Account_Count DESC;
      `);

      res.json(result.rows);
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
   }
});

app.get('/tags', async (req, res) => {
   try {
      const result = await pool.query(`
            SELECT t.id, t.name_ru, COUNT(td.tag_id) AS usage_count
            FROM tags t
            LEFT JOIN tags_detail td ON t.id = td.tag_id
            GROUP BY t.id, t.name_ru
            ORDER BY usage_count DESC;
         `);

      res.json(result.rows);
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
   }
});

app.get('/captcha', function (req, res) {
   const captcha = svgCaptcha.create();

   res.status(200).json({
      data: captcha.data,
      text: captcha.text,
   });
});

app.post("/register", async (req, res) => {
   const { login, password, email } = req.body;

   try {
      // Проверяем, есть ли уже пользователь с таким логином или email
      const checkUser = await pool.query("SELECT * FROM users WHERE login = $1 OR mail = $2", [login, email]);
      if (checkUser.rows.length > 0) {
         return res.status(400).json({ message: "Логин или email уже используются!" });
      }

      // Хэшируем пароль
      const hashedPass = await bcrypt.hash(password, 10);

      // Вставляем нового пользователя
      await pool.query(
         "INSERT INTO users (login, pass, date_of_create, mail) VALUES ($1, $2, $3, $4)",
         [login, hashedPass, new Date().toISOString().split("T")[0], email]
      );

      res.json({ success: true });
   } catch (error) {
      console.error("Ошибка при регистрации:", error);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post("/login", async (req, res) => {
   const { login, password } = req.body;

   try {
      // Получаем пользователя и его роль
      const userQuery = await pool.query(`
         SELECT users.*, roles.name AS role 
         FROM users
         LEFT JOIN roles ON users.id = roles.user_id
         WHERE users.login = $1
      `, [login]);

      if (userQuery.rows.length === 0) {
         return res.status(400).json({ message: "Неверный логин или пароль" });
      }

      const user = userQuery.rows[0];

      // Проверяем пароль
      const isMatch = await bcrypt.compare(password, user.pass);

      if (!isMatch) {
         return res.status(400).json({ message: "Неверный логин или пароль" });
      }

      // Генерируем новый sessionId
      const sessionId = uuidv4();

      // Обновляем session_id в базе данных
      await pool.query("UPDATE users SET session_id = $1 WHERE login = $2", [sessionId, login]);

      // Создаем JWT-токен
      const token = jwt.sign({ login, email: user.mail, sessionId, role: user.role }, JWT_SECRET, { expiresIn: "24h" });

      // Добавляем роль в объект user
      user.role = user.role || "user"; // если роли нет, ставим "user"

      res.json({ success: true, token, user });
   } catch (error) {
      console.error("Ошибка при логине:", error);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post("/send-code", async (req, res) => {
   try {
      const { login, code } = req.body;
      if (!login) return res.status(400).json({ error: "login обязателен" });

      const response = await pool.query("select * from users where login = $1", [login]);


      // Конфигурация почтового сервиса
      const transporter = nodemailer.createTransport({
         service: "gmail",
         auth: {
            user: process.env.EMAIL,
            pass: process.env.APP_PASSWORD,
         },
      });

      // Отправка письма
      await transporter.sendMail({
         from: process.env.EMAIL,
         to: response.rows[0].mail,
         subject: process.env.MAIL_TEXT,
         text: process.env.MAIL_SUBJECT.replace("{code}", code),
      });

      res.status(200).json({ message: "Код отправлен на почту" });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post("/recovery-password", async (req, res) => {
   try {
      const { login, newPassword } = req.body;
      if (!login || !newPassword) return res.status(400).json({ error: "Логин и новый пароль обязательны" });

      // Хешируем пароль
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      // Обновляем пароль в БД
      const result = await pool.query("UPDATE users SET pass = $1 WHERE login = $2 RETURNING id", [hashedPassword, login]);

      if (result.rowCount === 0) {
         return res.status(404).json({ error: "Пользователь не найден" });
      }

      res.json({ message: "Пароль успешно изменен" });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.get("/check-login/:login", async (req, res) => {
   try {
      const result = await pool.query("SELECT * FROM users WHERE login = $1", [req.params.login]);
      res.json(result.rows.length === 0);
   } catch (error) {
      console.error("Ошибка базы данных:", error);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.get("/get-role", async (req, res) => {
   const { user_id } = req.query

   try {
      const result = await pool.query("select * from roles where user_id = $1", [user_id])

      if (result.rows.length == 0) {
         return res.status(404).json({ error: 'У пользователя нет прав' });
      }

      res.status(201).json(result.rows[0]);
   } catch (error) {
      res.status(500).json({
         message: "Error geting role",
      });
   }
})

app.get('/comments', async (req, res) => {
   try {
      const { user_id } = req.query;

      if (!user_id) {
         return res.status(400).json({ error: 'user_id is required' });
      }

      const result = await pool.query(`
         SELECT 
            c.id, 
            c.parent_id, 
            c.account_id, 
            c.user_id, 
            c.text, 
            c.date_comment, 
            c.time_comment, 
            u.login AS author_nickname, 
            a.name AS account_name, 
            quoted_u.login AS quoted_author_nickname, 
            parent_comment.text AS quoted_comment_text
         FROM comments c
         LEFT JOIN users u ON c.user_id = u.id
         LEFT JOIN accounts a ON c.account_id = a.id
         LEFT JOIN comments parent_comment ON c.parent_id = parent_comment.id
         LEFT JOIN users quoted_u ON parent_comment.user_id = quoted_u.id
         WHERE c.user_id = $1
      `, [user_id]);

      res.json(result.rows);

   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.post("/add-comment", async (req, res) => {
   const { account_id, user_id, text, parent_id = null } = req.body;

   // Текущая дата и время
   const date_comment = new Date().toISOString().split('T')[0]; // Получаем только дату
   const time_comment = new Date().toISOString().split('T')[1].slice(0, 8); // Получаем время

   try {
      // Вставляем новый комментарий в таблицу comments
      const result = await pool.query(
         "INSERT INTO comments (account_id, user_id, text, parent_id, date_comment, time_comment) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
         [account_id, user_id, text, parent_id, date_comment, time_comment]
      );
      res.status(201).json({
         success: true,
         comment: result.rows[0], // Возвращаем добавленный комментарий
      });
   } catch (error) {
      console.error("Error adding comment:", error);
      res.status(500).json({
         success: false,
         message: "Error adding comment",
      });
   }
});

app.put("/update-comment", async (req, res) => {
   const { author_nickname, text, parent_id } = req.body;

   try {
      // Проверяем, существует ли комментарий с таким parent_id
      const existingComment = await pool.query(
         "SELECT * FROM comments WHERE id = $1",
         [parent_id]
      );

      if (existingComment.rows.length === 0) {
         return res.status(404).json({
            success: false,
            message: "Комментарий не найден",
         });
      }

      // Обновляем комментарий
      const updatedComment = await pool.query(
         "UPDATE comments SET text = $1 WHERE id = $2 RETURNING *",
         [text, parent_id]
      );

      res.status(200).json({
         success: true,
         message: "Комментарий обновлен",
         comment: updatedComment.rows[0],
      });
   } catch (error) {
      console.error("Error updating comment:", error);
      res.status(500).json({
         success: false,
         message: "Ошибка при обновлении комментария",
      });
   }
});

app.delete("/delete-comment", async (req, res) => {
   const { comment_id } = req.body;

   try {
      // Проверяем, существует ли комментарий с таким id
      const existingComment = await pool.query(
         "SELECT * FROM comments WHERE id = $1",
         [comment_id]
      );

      if (existingComment.rows.length === 0) {
         return res.status(404).json({
            success: false,
            message: "Комментарий не найден",
         });
      }

      // Удаляем комментарий
      await pool.query("DELETE FROM comments WHERE id = $1", [comment_id]);

      res.status(200).json({
         success: true,
         message: "Комментарий удален",
      });
   } catch (error) {
      console.error("Error deleting comment:", error);
      res.status(500).json({
         success: false,
         message: "Ошибка при удалении комментария",
      });
   }
});

app.get("/reports", async (req, res) => {
   try {
      const query = `
         SELECT 
            r.id,
            r.comment_id,
            r.reported_user_id,
            ru.login AS reported_user_login,
            r.reporter_user_id,
            su.login AS reporter_user_login,
            c.account_id, 
            a.name AS account_name,
            r.text AS report_text,
            c.text AS comment_text,  -- Добавляем текст самого комментария
            r.created_at
         FROM reports r
         JOIN users ru ON r.reported_user_id = ru.id
         JOIN users su ON r.reporter_user_id = su.id
         LEFT JOIN comments c ON r.comment_id = c.id  -- Привязка к комментариям
         LEFT JOIN accounts a ON c.account_id = a.id  -- Привязка к аккаунту через comment_id
         ORDER BY r.created_at DESC;
      `;

      const { rows } = await pool.query(query);
      res.json(rows);
   } catch (err) {
      console.error("Ошибка при получении жалоб:", err);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post('/add-reports', async (req, res) => {
   try {
      const { comment_id, reported_user_id, reporter_user_id, text } = req.body;

      if (!comment_id || !reported_user_id || !reporter_user_id || !text) {
         return res.status(400).json({ error: 'Все поля обязательны' });
      }

      // Проверяем, есть ли уже жалоба от этого пользователя на этот комментарий
      const existingReport = await pool.query(
         'SELECT id FROM reports WHERE comment_id = $1 AND reporter_user_id = $2',
         [comment_id, reporter_user_id]
      );

      if (existingReport.rows.length > 0) {
         return res.status(409).json({ error: 'Вы уже отправили жалобу на этот комментарий' });
      }

      // Если жалобы нет, добавляем новую
      const result = await pool.query(
         'INSERT INTO reports (comment_id, reported_user_id, reporter_user_id, text) VALUES ($1, $2, $3, $4) RETURNING *',
         [comment_id, reported_user_id, reporter_user_id, text]
      );

      res.status(201).json(result.rows[0]);
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Ошибка сервера' });
   }
});

app.delete('/delete-reports', async (req, res) => {
   try {
      const { id } = req.body;
      const result = await pool.query('DELETE FROM reports WHERE id = $1 RETURNING *', [id]);

      if (result.rowCount === 0) {
         return res.status(404).json({ error: 'Репорт не найден' });
      }

      res.json({ message: 'Репорт успешно удалён' });
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Ошибка сервера' });
   }
});

app.get('/favorites', async (req, res) => {
   try {
      const { users_id } = req.query;

      if (!users_id) {
         return res.status(400).json({ error: 'users_id обязательно' });
      }

      // Получаем информацию об аккаунтах, которые находятся в избранном
      const favoriteAccounts = await pool.query(
         `SELECT accounts.*, favorites.comment 
          FROM favorites
          JOIN accounts ON favorites.accounts_id = accounts.Id
          WHERE favorites.users_id = $1`,
         [users_id]
      );

      res.status(200).json(favoriteAccounts.rows);
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.post('/add-favorite', async (req, res) => {
   try {
      const { accounts_id, users_id, comment } = req.body;

      if (!accounts_id || !users_id) {
         return res.status(400).json({ error: 'accounts_id и users_id обязательны' });
      }

      // Проверяем, есть ли уже такая запись в избранном
      const existingFavorite = await pool.query(
         'SELECT id FROM favorites WHERE accounts_id = $1 AND users_id = $2',
         [accounts_id, users_id]
      );

      if (existingFavorite.rows.length > 0) {
         return res.status(409).json({ error: 'Этот аккаунт уже в избранном' });
      }

      // Добавляем в избранное
      const result = await pool.query(
         'INSERT INTO favorites (accounts_id, users_id, comment) VALUES ($1, $2, $3) RETURNING *',
         [accounts_id, users_id, comment]
      );

      res.status(201).json(result.rows[0]);
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Ошибка сервера' });
   }
});

app.delete('/delete-favorite', async (req, res) => {
   try {
      const { accounts_id, users_id } = req.body;

      if (!accounts_id || !users_id) {
         return res.status(400).json({ error: 'accounts_id и users_id обязательны' });
      }

      // Проверяем, есть ли запись в избранном
      const existingFavorite = await pool.query(
         'SELECT id FROM favorites WHERE accounts_id = $1 AND users_id = $2',
         [accounts_id, users_id]
      );

      if (existingFavorite.rows.length === 0) {
         return res.status(404).json({ error: 'Запись в избранном не найдена' });
      }

      // Удаляем из избранного
      await pool.query('DELETE FROM favorites WHERE accounts_id = $1 AND users_id = $2', [
         accounts_id,
         users_id
      ]);

      res.status(200).json({ message: 'Удалено из избранного' });
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Ошибка сервера' });
   }
});

app.post('/set-rate', (req, res) => {
   const { account_id, users_id, rate } = req.body;  // предполагаем, что данные передаются в теле запроса

   // Проверьте, что все поля заполнены
   if (account_id === undefined || users_id === undefined || rate === undefined) {
      return res.status(400).json({ error: 'Все поля должны быть заполнены' });
   }

   // Проверка, оставил ли уже пользователь оценку для этого аккаунта
   const checkSql = 'SELECT * FROM rating WHERE account_id = $1 AND users_id = $2';

   pool.query(checkSql, [account_id, users_id], (err, results) => {
      if (err) {
         console.error('Ошибка при проверке оценки:', err);
         return res.status(500).json({ error: 'Ошибка сервера' });
      }

      if (results.rows.length > 0) {
         // Если оценка уже есть, возвращаем ошибку
         return res.status(401).json({ error: 'Вы уже оставили оценку этому аккаунту' });
      }

      // Если оценки нет, вставляем новую запись (не передаем id)
      const sql = 'INSERT INTO rating (account_id, users_id, rate) VALUES ($1, $2, $3)';

      pool.query(sql, [account_id, users_id, rate], (err, results) => {
         if (err) {
            console.error('Ошибка при добавлении рейтинга:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
         }
         res.json({ message: 'Оценка успешно добавлена' });
      });
   });
});

app.post('/add-order', async (req, res) => {
   try {
      const { user_id, text, type } = req.body;
      if (!user_id || !text) {
         return res.status(400).json({ error: 'user_id и text обязательны' });
      }

      const query = `
         INSERT INTO orders (user_id, created_at, text, status, type) 
         VALUES ($1, NOW(), $2, 1, $3) 
         RETURNING *;
      `;

      const { rows } = await pool.query(query, [user_id, text, type]);
      res.status(201).json(rows[0]);
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.post('/check-rate', (req, res) => {
   const { account_id, users_id } = req.body;

   if (account_id === undefined || users_id === undefined) {
      return res.status(400).json({ error: 'Все поля должны быть заполнены' });
   }

   const checkSql = 'SELECT * FROM rating WHERE account_id = $1 AND users_id = $2';

   pool.query(checkSql, [account_id, users_id], (err, results) => {
      if (err) {
         console.error('Ошибка при проверке оценки:', err);
         return res.status(500).json({ error: 'Ошибка сервера' });
      }

      if (results.rows.length > 0) {
         res.json({ rated: true, rate: results.rows[0].rate });
      } else {
         res.json({ rated: false });
      }
   });
});

app.get('/get-orders', async (req, res) => {
   try {
      const { user_id, start_date, end_date, type } = req.query;
      let query = `SELECT * FROM orders`;
      let queryParams = [];
      let conditions = [];

      if (user_id) {
         conditions.push(`user_id = $${queryParams.length + 1}`);
         queryParams.push(user_id);
      }

      if (start_date && end_date) {
         conditions.push(`created_at BETWEEN $${queryParams.length + 1} AND $${queryParams.length + 2}`);
         queryParams.push(start_date, end_date);
      }

      if (type) {
         conditions.push(`type = $${queryParams.length + 1}`);
         queryParams.push(type);
      }

      if (conditions.length > 0) {
         query += ` WHERE ` + conditions.join(' AND ');
      }

      query += ` ORDER BY created_at DESC;`;

      const { rows } = await pool.query(query, queryParams);
      res.json(rows);
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.get('/get-admin-orders', async (req, res) => {
   try {
      const { user_id, start_date, end_date } = req.query;
      let query = `
         SELECT o.* 
         FROM orders o
         LEFT JOIN orders_deleted od ON o.id = od.order_id AND od.user_id = $1
         WHERE od.order_id IS NULL
      `;
      let queryParams = [user_id];
      let conditions = [];

      // Фильтрация по дате, если указаны start_date и end_date
      if (start_date && end_date) {
         conditions.push(`o.created_at BETWEEN $${queryParams.length + 1} AND $${queryParams.length + 2}`);
         queryParams.push(start_date, end_date);
      }

      // Если есть дополнительные условия, добавляем их в запрос
      if (conditions.length > 0) {
         query += ` AND ` + conditions.join(' AND ');
      }

      query += ` ORDER BY o.created_at DESC;`;

      // Выполнение запроса
      const { rows } = await pool.query(query, queryParams);
      res.json(rows);
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.put("/update-orders", async (req, res) => {
   try {
      const { id, status } = req.body;

      if (!id || status === undefined) {
         return res.status(400).json({ error: "id и status обязательны" });
      }

      const result = await pool.query(
         `UPDATE orders SET status = $1 WHERE id = $2 RETURNING *`,
         [status, id]
      );

      if (result.rowCount === 0) {
         return res.status(404).json({ error: "Запись не найдена" });
      }

      res.json({ message: "Статус успешно обновлен", data: result.rows[0] });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/delete-orders", async (req, res) => {
   try {
      const { id, user_id } = req.body;

      const result = await pool.query(
         `INSERT INTO orders_deleted(user_id, order_id) 
         VALUES ($1, $2)`,
         [user_id, id]
      );

      res.json(result.rows[0]);
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/send-messages", async (req, res) => {
   try {
      const { text_messages, user_from_id, user_to_login } = req.body;

      if (!text_messages || !user_from_id || !user_to_login) {
         return res.status(400).json({ error: "Все поля обязательны" });
      }

      const userToResult = await pool.query("SELECT id FROM users WHERE login = $1", [user_to_login]);

      if (userToResult.rows.length === 0) {
         return res.status(404).json({ error: "Получатель не найден" });
      }

      const user_to_id = userToResult.rows[0].id;

      const now = new Date();
      const date_messages = now.toISOString().split("T")[0]; // YYYY-MM-DD
      const time_messages = now.toTimeString().split(" ")[0]; // HH:MM:SS

      const result = await pool.query(
         `INSERT INTO messages (date_messages, time_messages, text_messages, user_from_id, user_to_id) 
          VALUES ($1, $2, $3, $4, $5) RETURNING *`,
         [date_messages, time_messages, text_messages, user_from_id, user_to_id]
      );

      res.status(201).json(result.rows[0]);
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.delete("/delete-messages", async (req, res) => {
   try {
      const { user_id, message_ids } = req.body;

      if (!user_id || !Array.isArray(message_ids) || message_ids.length === 0) {
         return res.status(400).json({ error: 'user_id и message_ids (массив) обязательны' });
      }

      // Убираем дубликаты
      const uniqueMessageIds = [...new Set(message_ids)];

      // Проверяем, какие сообщения уже скрыты (чтобы не дублировать)
      const existingDeleted = await pool.query(
         `SELECT message_id FROM messages_deleted WHERE user_id = $1 AND message_id = ANY($2)`,
         [user_id, uniqueMessageIds]
      );

      const alreadyDeletedIds = existingDeleted.rows.map(row => row.message_id);

      // Фильтруем только новые сообщения, которых нет в `messages_deleted`
      const newMessageIds = uniqueMessageIds.filter(id => !alreadyDeletedIds.includes(id));

      if (newMessageIds.length === 0) {
         return res.status(400).json({ error: 'Все сообщения уже скрыты' });
      }

      // Массовое добавление новых скрытых сообщений
      const values = newMessageIds.map(id => `(${user_id}, ${id})`).join(",");

      await pool.query(
         `INSERT INTO messages_deleted (user_id, message_id) VALUES ${values}`
      );

      res.json({ success: true, message: "Сообщения скрыты", hidden_messages: newMessageIds });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get("/get-messages", async (req, res) => {
   try {
      const { user_id } = req.query;

      if (!user_id) {
         return res.status(400).json({ error: 'user_id обязателен' });
      }

      const result = await pool.query(
         `SELECT m.id, m.date_messages, m.time_messages, m.text_messages, 
               u1.login AS sender, u2.login AS receiver
         FROM messages m
         JOIN users u1 ON m.user_from_id = u1.id
         JOIN users u2 ON m.user_to_id = u2.id
         LEFT JOIN messages_deleted d 
            ON m.id = d.message_id AND d.user_id = $1
         WHERE (m.user_to_id = $1 OR m.user_from_id = $1)
         AND d.message_id IS NULL  -- Исключаем скрытые пользователем сообщения
         ORDER BY m.date_messages DESC, m.time_messages DESC`,
         [user_id]
      );

      res.json(result.rows);
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get('/get-user', async (req, res) => {
   try {
      const { login } = req.query;

      if (!login) {
         return res.status(400).json({ error: 'Логин обязателен' });
      }

      const query = `
         SELECT u.id, u.login, u.avatar, u.date_of_create, u.mail, u.session_id, 
               COALESCE(r.name, '') AS role
         FROM users u
         LEFT JOIN roles r ON u.id = r.user_id
         WHERE u.login = $1
      `;

      const { rows } = await pool.query(query, [login]);

      if (rows.length === 0) {
         return res.status(404).json({ error: 'Пользователь не найден' });
      }

      res.json(rows[0]);
   } catch (err) {
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.post('/change-user-avatar', uploadPhoto.single("photo"), async (req, res) => {
   try {
      const { id } = req.body;
      const photoBuffer = req.file.buffer; // Получаем бинарные данные фото

      // Обновляем поле 'photo' в базе данных
      const result = await pool.query(
         `UPDATE users
            SET avatar = $1
            WHERE id = $2 
            RETURNING *`, // Возвращаем все данные пользователя
         [photoBuffer, id]
      );

      res.json(result.rows[0]);
   } catch (error) {
      res.status(500).json({ error: 'Ошибка сервера', message: error.message });
   }
})

app.post("/add-role", async (req, res) => {
   try {
      const { user_id, role_name } = req.body;

      if (!user_id || !role_name) {
         return res.status(400).json({ error: "user_id и role_name обязательны" });
      }

      // Если передана роль "user", удаляем запись из таблицы roles
      if (role_name === "user") {
         const deleteQuery = `DELETE FROM roles WHERE user_id = $1 RETURNING *;`;
         const { rows } = await pool.query(deleteQuery, [user_id]);

         if (rows.length === 0) {
            return res.json({ message: "Роль уже отсутствует у пользователя." });
         }

         return res.json({ message: "Роль пользователя успешно удалена." });
      }

      const upsertQuery = `
         INSERT INTO roles (user_id, name)
         VALUES ($1, $2)
         ON CONFLICT (user_id) 
         DO UPDATE SET name = EXCLUDED.name
         RETURNING *;
      `;

      const { rows } = await pool.query(upsertQuery, [user_id, role_name]);

      res.json({ message: "Роль успешно обновлена", data: rows[0] });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.delete("/delete-user", async (req, res) => {
   try {
      const { user_id } = req.body;

      if (!user_id) {
         return res.status(400).json({ error: "user_id обязателен" });
      }

      const query = `DELETE FROM users WHERE id = $1 RETURNING *;`;

      const { rows } = await pool.query(query, [user_id]);

      if (rows.length === 0) {
         return res.status(404).json({ error: "Пользователь не найден" });
      }

      res.json({ message: "Пользователь успешно удалён", data: rows[0] });
   } catch (err) {
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/upload-file", upload.single("file"), async (req, res) => {
   try {
      if (!req.file) return res.status(400).json({ error: "Файл не найден" });

      const accounts = await parseTxtFile(req.file.path);

      console.log(accounts);

      fs.unlinkSync(req.file.path);

      if (!Array.isArray(accounts)) {
         return res.status(400).json({ error: "accounts не является массивом" });
      }

      for (const account of accounts) {
         const identificator = account.id;
         if (!identificator) return res.status(400).json({ error: "Нет идентификатора" });

         // === Добавление города ===
         let cityResult = await pool.query("SELECT id FROM city WHERE name_ru = $1", [account.city]);
         let cityId = cityResult.rows.length ? cityResult.rows[0].id : null;

         if (!cityId && account.city) {
            let insertCity = await pool.query(
               `INSERT INTO city (name_ru, name_eu) VALUES ($1, $2) 
               ON CONFLICT (name_ru) DO NOTHING RETURNING id`,
               [account.city, account.city]
            );

            cityId = insertCity.rows.length ? insertCity.rows[0].id : null;
            if (!cityId) {
               cityId = (await pool.query("SELECT id FROM city WHERE name_ru = $1", [account.city])).rows[0].id;
            }
         }

         // === Определение даты рождения ===
         let dateOfBirth = null;
         if (account.dr) {
            let currentYear = new Date().getFullYear();
            let birthYear = currentYear - parseInt(account.dr, 10);
            dateOfBirth = `${birthYear}-01-01`;
         }

         const accountResult = await pool.query(
            `INSERT INTO accounts (name, identificator, check_video, "City_id", date_of_create, date_of_birth) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
            [
               account.title,
               identificator,
               account.nvideo === "1" ? 1 : 0,
               cityId,
               account.date_of_create == null ? null : account.date_of_create ? account.date_of_create : new Date().toISOString(),
               dateOfBirth
            ]
         );

         const accountId = accountResult.rows[0].id;

         // === Добавление тегов ===
         let tags = account.tags || "";
         tags = tags.split(",").map(tag => tag.trim()).filter(tag => tag.length > 0);

         for (const tag of tags) {
            let tagResult = await pool.query("SELECT id FROM tags WHERE name_ru = $1", [tag]);

            let tagId = tagResult.rows.length ? tagResult.rows[0].id : null;

            if (!tagId) {
               let insertTagResult = await pool.query(
                  `INSERT INTO tags (name_ru, name_eu) 
                   VALUES ($1, $1) 
                   RETURNING id`,
                  [tag]
               );
               tagId = insertTagResult.rows[0].id;
            }

            await pool.query(
               `INSERT INTO tags_detail (tag_id, account_id) 
                VALUES ($1, $2) 
                ON CONFLICT (tag_id, account_id) DO NOTHING`,
               [tagId, accountId]
            );
         }

         // === Создание папки для аккаунта ===
         const folderPath = path.join(__dirname, "fileBase", identificator);
         if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath, { recursive: true });

         const socialTypes = {
            fb: "fb",
            od: "od",
            icq: "icq",
            insta: "insta",
            tw: "tw",
            email: "email",
            tg: "tg",
            tik: "tik",
            of: "of",
            tel: "tel"
         };

         for (const [key, identificator] of Object.entries(socialTypes)) {
            if (account[key]) {
               let socialTypeResult = await pool.query("SELECT id FROM socials_type WHERE identificator = $1", [identificator]);
               let typeSocialId = socialTypeResult.rows.length ? socialTypeResult.rows[0].id : null;

               if (typeSocialId) {
                  let insertSocialResult = await pool.query(
                     `INSERT INTO socials (type_social_id, text) 
                      VALUES ($1, $2) 
                      ON CONFLICT (type_social_id, text) DO NOTHING RETURNING id`,
                     [typeSocialId, account[key]]
                  );


                  let socialId = insertSocialResult.rows.length > 0 ? insertSocialResult.rows[0].id : null;

                  if (!socialId) {
                     let existingSocial = await pool.query(
                        `SELECT id FROM socials WHERE type_social_id = $1 AND text = $2`,
                        [typeSocialId, account[key]]
                     );
                     socialId = existingSocial.rows[0]?.id;
                  }

                  if (socialId) {
                     await pool.query(
                        `INSERT INTO socials_detail (account_id, socials_id) 
                         VALUES ($1, $2)`,
                        [accountId, socialId]
                     );
                  }

               }
            }
         }
      }

      res.json({ success: true });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/account-edit-media", upload.array("files"), (req, res) => {
   try {
      const id = req.query.id;

      if (!id) {
         return res.status(400).json({ success: false, message: "Отсутствует id" });
      }

      const folderPath = path.join(__dirname, "fileBase", id);
      if (!fs.existsSync(folderPath)) {
         fs.mkdirSync(folderPath, { recursive: true });
      }

      let incomingLinks = [];
      if (req.body.links) {
         try {
            incomingLinks = JSON.parse(req.body.links);
            incomingLinks = incomingLinks.filter(item => typeof item === "string");
         } catch (error) {
            console.error("Ошибка парсинга JSON:", error);
         }
      }

      // Получаем файлы в папке
      let existingFiles = fs.readdirSync(folderPath);

      // Получаем все занятые номера
      let usedNumbers = existingFiles.map(file => parseInt(file.split(".")[0])).filter(num => !isNaN(num));

      // Функция для поиска первого свободного номера
      const getNextNumber = (usedNumbers, start) => {
         let number = start;
         while (usedNumbers.includes(number)) number++;
         usedNumbers.push(number); // Добавляем в занятые, чтобы избежать дублирования
         return number;
      };

      let uploadedFiles = [];

      req.files.forEach((file) => {
         let ext = path.extname(file.originalname).toLowerCase();
         let newNumber = /\.(mp4|mov|avi|mkv)$/i.test(ext)
            ? getNextNumber(usedNumbers, 200)  // Видео от 200 и выше
            : getNextNumber(usedNumbers, 1);   // Картинки от 1 до 199

         let newFileName = `${newNumber}${ext}`;
         let newPath = path.join(folderPath, newFileName);

         fs.renameSync(file.path, newPath);
         uploadedFiles.push(`/fileBase/${id}/${newFileName}`);
      });

      // Обновляем списки файлов
      existingFiles = fs.readdirSync(folderPath);
      let incomingFileNames = incomingLinks.map(link => path.basename(link));
      let uploadedFileNames = uploadedFiles.map(link => path.basename(link));

      // Удаляем файлы, которых нет в `incomingFileNames` и `uploadedFileNames`
      existingFiles.forEach((file) => {
         if (!incomingFileNames.includes(file) && !uploadedFileNames.includes(file)) {
            try {
               fs.unlinkSync(path.join(folderPath, file));
            } catch (err) {
            }
         }
      });

      // Возвращаем список файлов после обновления
      const updatedFiles = fs.readdirSync(folderPath).map(file => `/fileBase/${id}/${file}`);

      res.json({ success: true, message: "Файлы загружены", files: updatedFiles });
   } catch (error) {
      console.error("Ошибка:", error);
      res.status(500).json({ success: false, message: "Ошибка на сервере" });
   }
});

app.delete("/delete-account", async (req, res) => {
   try {
      const { account_id, account_identificator } = req.body;
      if (!account_id) {
         return res.status(400).json({ error: "account_id обязателен" });
      }

      // Удаляем запись из базы данных
      const { rowCount } = await pool.query(`DELETE FROM accounts WHERE id = $1;`, [account_id]);

      if (rowCount === 0) {
         return res.status(404).json({ error: "Аккаунт не найден" });
      }

      // Путь к папке аккаунта
      const folderPath = path.join(__dirname, "fileBase", account_identificator);

      // Проверяем, существует ли папка
      if (fs.existsSync(folderPath)) {
         fs.rmSync(folderPath, { recursive: true, force: true }); // Удаляем папку и её содержимое
      }

      res.json({ message: "Аккаунт и его файлы успешно удалены" });
   } catch (error) {
      console.error("Ошибка при удалении аккаунта:", error);
      res.status(500).json({ error: "Ошибка сервера", message: error.message });
   }
});

app.post("/save-sections", upload.array('files'), async (req, res) => {
   try {
      const { page_name } = req.body;
      const sections = Array.isArray(req.body.sections) ? req.body.sections : JSON.parse(req.body.sections);

      const sectionDir = path.join(__dirname, "pages", page_name);

      // Удаляем все секции с указанным page_name из БД
      await pool.query(`DELETE FROM sections WHERE page_name = $1`, [page_name]);

      // Если папка уже существует, удаляем её вместе с содержимым
      if (fs.existsSync(sectionDir)) {
         fs.rmSync(sectionDir, { recursive: true, force: true });
      }

      // Создаем новую директорию для изображений
      fs.mkdirSync(sectionDir, { recursive: true });

      for (const section of sections) {
         const { section_order, layout_id, content } = section;

         // Вставляем новую секцию в БД
         await pool.query(
            `INSERT INTO sections (page_name, section_order, layout_id, content) 
            VALUES ($1, $2, $3, $4)`,
            [page_name, section_order, layout_id, content]
         );

         // Проверяем, есть ли файлы для сохранения
         if (req.files && req.files.length > 0) {
            req.files.forEach((file) => {
               const tempFilePath = path.join(__dirname, "fileBase", file.filename);  // Временный файл
               const newFilePath = path.join(sectionDir, file.originalname);  // Новый путь

               try {
                  fs.renameSync(tempFilePath, newFilePath);  // Перемещаем файл
               } catch (error) {
               }
            });
         }
      }

      res.json({ message: "Секции успешно сохранены!" });
   } catch (error) {
      console.error("Ошибка при сохранении секций:", error);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post("/update-photo", uploadPhoto.single("photo"), async (req, res) => {
   try {
      const { id } = req.body; // Получаем ID пользователя
      const photoBuffer = req.file.buffer; // Получаем бинарные данные фото

      // Обновляем поле 'photo' в базе данных
      const result = await pool.query(
         `UPDATE accounts
            SET photo = $1
            WHERE id = $2 RETURNING photo`,
         [photoBuffer, id] // Передаем бинарные данные как bytea
      );

      // Проверяем результат
      const updatedPhoto = result.rows[0]?.photo;

      res.json({ message: "Фото успешно обновлено", result: { photo: updatedPhoto } });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/update-account-date", async (req, res) => {
   try {
      const { id, new_date_of_create } = req.body; // Дата и ID аккаунта

      const result = await pool.query(
         `UPDATE accounts
          SET date_of_create = $1
          WHERE id = $2
          RETURNING *`,  // Возвращаем обновленную строку для проверки
         [new_date_of_create, id]
      );

      // Если аккаунт найден и обновлен
      if (result.rows.length > 0) {
         res.json(result.rows[0]);  // Возвращаем обновленный аккаунт
      } else {
         res.status(404).json({ error: "Аккаунт не найден" });
      }
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.put("/update-account", async (req, res) => {
   try {
      const { id, name, city, tags } = req.body;

      if (!id) {
         return res.status(400).json({ error: "ID аккаунта обязателен" });
      }

      await pool.query("BEGIN"); // Начинаем транзакцию

      // 1. Обновление имени аккаунта
      if (name) {
         await pool.query(
            `UPDATE accounts SET name = $1 WHERE id = $2`,
            [name, id]
         );
      }

      let cityId = null;

      // 2. Работа с городом
      if (city) {
         const cityResult = await pool.query(
            `SELECT id FROM city WHERE name_ru = $1 OR name_eu = $1`,
            [city]
         );

         if (cityResult.rows.length > 0) {
            cityId = cityResult.rows[0].id;
         } else {
            const newCity = await pool.query(
               `INSERT INTO city (name_ru, name_eu) VALUES ($1, $1) RETURNING id`,
               [city]
            );
            cityId = newCity.rows[0].id;
         }

         await pool.query(
            `UPDATE accounts SET "City_id" = $1 WHERE id = $2`,
            [cityId, id]
         );
      }

      // 3. Работа с тегами
      const tagList = tags ? tags.split(",").map((t) => t.trim()) : [];

      // Получаем все текущие теги аккаунта
      const existingTags = await pool.query(
         `SELECT tag_id FROM tags_detail WHERE account_id = $1`,
         [id]
      );
      const existingTagIds = existingTags.rows.map(row => row.tag_id);

      const newTagIds = [];

      for (const tag of tagList) {
         let tagId;

         // Проверяем, существует ли тег
         const tagResult = await pool.query(
            `SELECT id FROM tags WHERE name_ru = $1 OR name_eu = $1`,
            [tag]
         );

         if (tagResult.rows.length > 0) {
            tagId = tagResult.rows[0].id;
         } else {
            // Добавляем новый тег
            const newTag = await pool.query(
               `INSERT INTO tags (name_ru, name_eu) VALUES ($1, $1) RETURNING id`,
               [tag]
            );
            tagId = newTag.rows[0].id;
         }

         newTagIds.push(tagId);

         // Проверяем, есть ли связь с аккаунтом
         const tagDetailResult = await pool.query(
            `SELECT id FROM tags_detail WHERE tag_id = $1 AND account_id = $2`,
            [tagId, id]
         );

         if (tagDetailResult.rows.length === 0) {
            // Если нет, создаем связь
            await pool.query(
               `INSERT INTO tags_detail (tag_id, account_id) VALUES ($1, $2)`,
               [tagId, id]
            );
         }
      }

      // 4. Удаление старых тегов, которые не переданы в запросе
      const tagsToRemove = existingTagIds.filter(tagId => !newTagIds.includes(tagId));

      if (tagsToRemove.length > 0) {
         await pool.query(
            `DELETE FROM tags_detail WHERE account_id = $1 AND tag_id = ANY($2)`,
            [id, tagsToRemove]
         );
      }

      await pool.query("COMMIT"); // Фиксируем изменения

      res.json({ message: "Аккаунт успешно обновлен" });
   } catch (err) {
      await pool.query("ROLLBACK"); // Откатываем изменения в случае ошибки
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get('/sections', async (req, res) => {
   try {
      const { page_name } = req.query;
      if (!page_name) {
         return res.status(400).json({ message: "Необходимо указать page_name" });
      }

      const sectionsQuery = await pool.query(
         "SELECT * FROM sections WHERE page_name = $1 ORDER BY section_order",
         [page_name]
      );

      if (sectionsQuery.rows.length === 0) {
         return res.status(404).json({ message: "Секции не найдены" });
      }

      let sections = sectionsQuery.rows;

      const sectionPath = path.join(__dirname, 'pages', `${page_name}`);
      let images = fs.readdirSync(sectionPath)
         .filter(file => file.endsWith('.jpg') || file.endsWith('.png'))
         .map(file => `/uploads/${page_name}/${file}`);

      res.json({ sections, images });
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.use('/uploads', express.static(path.join(__dirname, 'pages')));



// Запуск сервера
app.listen(port, () => {
   console.log(`Сервер запущен на порту ${port}`);
});