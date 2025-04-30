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
import {
   createDirectory,
   exists,
   listFiles,
   uploadFile,
   deleteFile,
   getPublicUrl,
   deleteRemoteDirectory
} from './sftp-utils.js';

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

const xssOptions = {
   whiteList: {
      // Добавляем все теги, которые хотим поддерживать
      span: ['class'],
      b: [],
      i: [],
      u: [],
      s: [],
      strong: [],
      em: [],
      br: [],
      h1: [],
      h2: [],
      h3: [],
      blockquote: [],
      pre: [],
      code: [],
      ol: [],
      ul: [],
      li: [],
      p: ['class']
      // Добавьте другие разрешенные теги по необходимости
   }
};

const customXss = new xss.FilterXSS(xssOptions);

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
            obj[key] = customXss.process(obj[key]); // Используем настроенный фильтр
         }
      }
   }

   // Остальной код middleware остается без изменений
   if (req.body) {
      sanitizeObject(req.body);
   }
   if (req.query) {
      sanitizeObject(req.query);
   }
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

      const readyAccounts = [];

      // Разделяем контент файла на блоки аккаунтов (каждый начинается с тега <title>)
      const accountBlocks = fileContent.split(/<title>/).filter(block => block.trim() !== '');

      for (let block of accountBlocks) {
         block = '<title>' + block; // Восстанавливаем тег <title> который был удален при сплите

         // Извлекаем основные данные
         const titleMatch = /<title>(.*?)<\/title>/.exec(block);
         const idMatch = /<id>(.*?)<\/id>/.exec(block);
         const dateMatch = /<date>(.*?)<\/date>/.exec(block);

         if (!titleMatch || !idMatch) continue; // Пропускаем блок если нет основных данных

         const title = titleMatch[1];
         const id = idMatch[1];
         const dateValue = dateMatch ? dateMatch[1] : '';

         // Проверка идентификатора
         if (!id) continue;

         let date_of_create;
         if (!dateValue || dateValue.trim() === '') {
            date_of_create = null;
         } else {
            date_of_create = dateValue.trim();
         }

         // Функция для извлечения всех значений для определенного тега
         const getAllValues = (tag) => {
            const pattern = new RegExp(`<${tag}>(.*?)<\/${tag}>`, 'g');
            const values = [];
            let match;
            while ((match = pattern.exec(block)) !== null) {
               if (match[1].trim() !== '') {
                  values.push(match[1].trim());
               }
            }
            return values;
         };

         // Получаем первое значение (для одиночных полей)
         const getFirstValue = (tag) => {
            const values = getAllValues(tag);
            return values.length > 0 ? values[0] : '';
         };

         const accountData = {
            title,
            id,
            dr: getFirstValue('dr'),
            city: getFirstValue('city'),
            // Для всех социальных сетей получаем все значения
            skype: getAllValues('skype'),
            icq: getAllValues('icq'),
            fb: getAllValues('fb'),
            od: getAllValues('od'),
            insta: getAllValues('insta'),
            tw: getAllValues('tw'),
            girl: getFirstValue('girl'),
            boy: getFirstValue('boy'),
            vk: getFirstValue('vk'),
            email: getAllValues('email'),
            tg: getAllValues('tg'),
            tik: getAllValues('tik'),
            of: getAllValues('of'),
            tel: getAllValues('tel'),
            nvideo: getFirstValue('nvideo'),
            tags: getFirstValue('tags'),
            date_of_create,
         };

         readyAccounts.push(accountData);
      }

      // Если нет данных, возвращаем ошибку
      if (readyAccounts.length === 0) {
         return reject(new Error('Нет данных аккаунтов в файле'));
      }

      resolve(readyAccounts);
   });
}

app.get('/accounts', async (req, res) => {
   try {
      let { search, city_id, tag_id, date_range, page = 1, limit = 40, admin_mode = 'false', sort_by_rating = 'false' } = req.query;
      page = parseInt(page);
      limit = parseInt(limit);
      const offset = (page - 1) * limit;

      let queryBase = '';

      // В зависимости от sort_by_rating используем разные базовые запросы
      if (sort_by_rating === 'true') {
         queryBase = `
            FROM accounts a
            LEFT JOIN (
               SELECT
                  account_id,
                  AVG(rate) as average_rating,
                  COUNT(id) as rating_count
               FROM rating
               GROUP BY account_id
            ) r ON a.id = r.account_id
            LEFT JOIN tags_detail td ON a.id = td.account_id
            LEFT JOIN tags t ON td.tag_id = t.id
            LEFT JOIN city c ON a."City_id" = c.id
         `;
      } else {
         queryBase = `
            FROM accounts a
            LEFT JOIN tags_detail td ON a.id = td.account_id
            LEFT JOIN tags t ON td.tag_id = t.id
            LEFT JOIN city c ON a."City_id" = c.id
         `;
      }

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

      // Фильтр по дате создания (только для не-админского режима)
      if (admin_mode !== 'true') {
         const currentDate = new Date().toISOString().split('T')[0];
         conditions.push(`a.date_of_create IS NOT NULL AND a.date_of_create::DATE <= $${queryParams.length + 1}::DATE`);
         queryParams.push(currentDate);
      }

      // Применяем фильтры
      let whereClause = conditions.length > 0 ? " WHERE " + conditions.join(" AND ") : "";

      // Получаем общее количество записей
      const countQuery = `SELECT COUNT(DISTINCT a.id) AS total ${queryBase} ${whereClause}`;
      const countResult = await pool.query(countQuery, queryParams);
      const totalItems = countResult.rows[0].total;
      const totalPages = Math.ceil(totalItems / limit);

      // Определяем поля выборки и порядок сортировки в зависимости от режима
      let selectClause = '';
      let orderByClause = '';

      if (sort_by_rating === 'true') {
         // Для сортировки по рейтингу добавляем все необходимые поля в SELECT
         selectClause = `
            SELECT DISTINCT 
               a.id, 
               a.name, 
               a."City_id", 
               a.date_of_create, 
               a.date_of_birth, 
               a.identificator, 
               a.photo, 
               a.check_video,
               COALESCE(r.average_rating, 0) as average_rating,
               COALESCE(r.rating_count, 0) as rating_count,
               COALESCE((r.average_rating * r.rating_count + 3) / (r.rating_count + 1), 0) as weighted_rating
         `;

         orderByClause = `
            ORDER BY 
               weighted_rating DESC, 
               rating_count DESC, 
               average_rating DESC,
               a.id ASC
         `;
      } else {
         // Стандартная выборка и сортировка с добавлением ID как второго критерия
         selectClause = `
            SELECT DISTINCT 
               a.id, 
               a.name, 
               a."City_id", 
               a.date_of_create, 
               a.date_of_birth, 
               a.identificator, 
               a.photo, 
               a.check_video
         `;

         orderByClause = `ORDER BY a.date_of_create DESC, a.id ASC`;
      }

      // Составляем финальный запрос
      let query = `
         ${selectClause}
         ${queryBase} 
         ${whereClause}
         ${orderByClause}
         LIMIT $${queryParams.length + 1} OFFSET $${queryParams.length + 2}
      `;

      queryParams.push(limit, offset);
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

      res.json({
         accounts,
         totalPages
      });

   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.get('/top-accounts', async (req, res) => {
   try {
      const limit = 3; // Получаем топ-10 аккаунтов

      let queryBase = `
         FROM accounts a
         LEFT JOIN (
            SELECT 
               account_id, 
               AVG(rate) as average_rating,
               COUNT(id) as rating_count
            FROM rating
            GROUP BY account_id
         ) r ON a.id = r.account_id
         LEFT JOIN city c ON a."City_id" = c.id
      `;

      // Получаем топ аккаунтов
      let query = `
         SELECT 
            a.id, 
            a.name, 
            a."City_id", 
            a.date_of_create, 
            a.date_of_birth, 
            a.identificator, 
            a.photo, 
            a.check_video,
            COALESCE(r.average_rating, 0) as average_rating,
            COALESCE(r.rating_count, 0) as rating_count,
            /* Формула для расчета рейтинга с учетом количества оценок */
            COALESCE(
               (r.average_rating * r.rating_count + 3) / (r.rating_count + 1),
               0
            ) as weighted_rating
         ${queryBase} 
         ORDER BY weighted_rating DESC, rating_count DESC, average_rating DESC
         LIMIT $1
      `;

      const result = await pool.query(query, [limit]);
      let accounts = result.rows;

      // Проверяем фото (код такой же, как в исходном запросе)
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

      res.json({
         accounts
      });

   } catch (err) {
      console.error('Error:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.get('/get-all-account-dates', async (req, res) => {
   try {
      // Запрос только для получения всех дат создания аккаунтов
      const query = `
       SELECT DISTINCT to_char(date_of_create, 'YYYY-MM-DD') as account_date
       FROM accounts
       WHERE date_of_create IS NOT NULL
       ORDER BY account_date
     `;

      const result = await pool.query(query);

      // Извлекаем даты из результата запроса
      const dates = result.rows.map(row => row.account_date);

      res.json({ dates });
   } catch (err) {
      console.error('Ошибка при получении дат аккаунтов:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.get('/account', async (req, res) => {
   try {
      const { id } = req.query;

      // Получаем данные аккаунта
      const userQuery = await pool.query("SELECT * FROM accounts WHERE Id = $1", [id]);
      if (userQuery.rows.length === 0) {
         return res.status(400).json({ message: "Пользователь не найден" });
      }
      const user = userQuery.rows[0];

      // Получаем данные города
      const cityQuery = await pool.query(`SELECT * FROM city WHERE id = $1`, [user.City_id]);
      const city = cityQuery.rows[0];

      // Получаем теги
      const tagsQuery = await pool.query(`
         SELECT tags.id, tags.name_ru, tags.name_eu
         FROM tags
         JOIN tags_detail ON tags.id = tags_detail.tag_id
         WHERE tags_detail.account_id = $1
      `, [id]);
      const tags = tagsQuery.rows;

      // Получаем данные о соцсетях
      const socialsQuery = await pool.query(`
         SELECT socials.id, socials.type_social_id, socials.text, socials_type.name AS social_name
         FROM socials
         JOIN socials_type ON socials.type_social_id = socials_type.id
         JOIN socials_detail ON socials.id = socials_detail.socials_id
         WHERE socials_detail.account_id = $1
      `, [id]);
      const socials = socialsQuery.rows;

      // Получаем рейтинг
      const ratingQuery = await pool.query(`SELECT * FROM rating WHERE account_id = $1`, [id]);
      const rating = ratingQuery.rows;

      // Получаем количество просмотров
      const viewsQuery = await pool.query(`SELECT COUNT(*) FROM account_views WHERE account_id = $1`, [id]);
      const viewsCount = parseInt(viewsQuery.rows[0].count);

      // Получаем комментарии
      const commentsQuery = await pool.query(`
         SELECT comments.*, 
            TO_CHAR(comments.date_comment, 'YYYY-MM-DD') as date_comment,
            comments.time_comment,
            users.login AS author_nickname
         FROM comments
         JOIN users ON comments.user_id = users.id
         WHERE comments.account_id = $1
         ORDER BY comments.date_comment DESC, comments.time_comment DESC
      `, [id]);
      const commentsTree = buildCommentTree(commentsQuery.rows);

      // Получаем детали пользователя
      const userDetailsQuery = await pool.query(`SELECT * FROM users WHERE login = $1`, [user.login]);
      const userDetails = userDetailsQuery.rows[0];

      // 📂 Получаем файлы с SFTP-сервера
      const remotePath = user.identificator;
      let files = [];

      // Проверяем, что у нас есть идентификатор пользователя
      if (remotePath) {
         try {
            // Проверяем существование директории перед запросом списка файлов
            const dirExists = await exists(remotePath);
            if (dirExists) {
               // Получаем список файлов из директории пользователя
               const filesList = await listFiles(remotePath);
               // Фильтруем только изображения и видео и формируем URL-адреса
               files = filesList
                  .filter(file => file.endsWith('.jpg') || file.endsWith('.png') || file.endsWith('.mp4'))
                  .map(file => getPublicUrl(`/${remotePath}/${file}`));
               console.log(`Получено ${files.length} файлов для пользователя ${remotePath}`);
            } else {
               console.log(`Директория ${remotePath} не существует на SFTP`);
            }
         } catch (fileErr) {
            console.error(`Ошибка получения файлов с SFTP для ${remotePath}:`, fileErr);
            // Продолжаем выполнение, даже если не удалось получить файлы
         }
      } else {
         console.log('Отсутствует identificator пользователя');
      }

      // Добавляем количество просмотров к объекту пользователя
      user.views = viewsCount;

      // Собираем финальный объект
      const fullAccountInfo = {
         account: user,
         city: city,
         tags: tags,
         socials: socials,
         rating: rating,
         comments: commentsTree,
         userDetails: userDetails,
         files: files
      };

      res.json(fullAccountInfo);
   } catch (err) {
      console.error('Error in account endpoint:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.post('/add-view', async (req, res) => {
   try {
      const { accounts_id, user_id = null } = req.body;

      // Проверяем существование аккаунта
      const accountCheck = await pool.query("SELECT * FROM accounts WHERE Id = $1", [accounts_id]);
      if (accountCheck.rows.length === 0) {
         return res.status(400).json({ message: "Аккаунт не найден" });
      }

      // Добавляем запись о просмотре
      await pool.query(
         "INSERT INTO account_views (user_id, account_id) VALUES ($1, $2)",
         [user_id, accounts_id]
      );

      // Возвращаем количество просмотров для этого аккаунта
      const viewsCount = await pool.query(
         "SELECT COUNT(*) FROM account_views WHERE account_id = $1",
         [accounts_id]
      );

      res.status(200).json({
         success: true,
         views: parseInt(viewsCount.rows[0].count)
      });
   } catch (err) {
      console.error('Error in add-view endpoint:', err);
      res.status(500).json({ error: 'Server error', message: err.message });
   }
});

app.get('/cities', authMiddleware, async (req, res) => {
   try {
      const currentDate = new Date().toISOString().split('T')[0]; // Получаем текущую дату в формате YYYY-MM-DD

      const result = await pool.query(`
         SELECT
            c.id AS City_ID,
            c.name_ru AS City_Name,
            COUNT(a.id) AS Account_Count
         FROM accounts a
         JOIN city c ON a."City_id" = c.id
         WHERE a.date_of_create IS NOT NULL AND a.date_of_create <= $1
         GROUP BY c.id, c.name_ru
         ORDER BY Account_Count DESC;
      `, [currentDate]);

      res.json(result.rows);
   } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Server error' });
   }
});

app.get('/tags', async (req, res) => {
   try {
      const currentDate = new Date().toISOString().split('T')[0]; // Получаем текущую дату в формате YYYY-MM-DD

      const result = await pool.query(`
         SELECT 
            t.id, 
            t.name_ru, 
            COUNT(CASE WHEN a.id IS NOT NULL AND a.date_of_create IS NOT NULL AND a.date_of_create <= $1 THEN td.tag_id END) AS usage_count
         FROM tags t
         LEFT JOIN tags_detail td ON t.id = td.tag_id
         LEFT JOIN accounts a ON td.account_id = a.id
         GROUP BY t.id, t.name_ru
         ORDER BY usage_count DESC;
      `, [currentDate]);

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
         return res.status(201).json({
            id: new Date(),
            name: 'user',
            user_id,
         });
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
   // Store date and time in UTC format
   const now = new Date();
   const date_comment = now.toISOString().split('T')[0]; // Get date in YYYY-MM-DD format (UTC)
   const time_comment = now.toISOString().split('T')[1].slice(0, 8); // Get time in HH:MM:SS format (UTC)

   try {
      // Insert the new comment into the comments table
      const result = await pool.query(
         "INSERT INTO comments (account_id, user_id, text, parent_id, date_comment, time_comment) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
         [account_id, user_id, text, parent_id, date_comment, time_comment]
      );
      res.status(201).json({
         success: true,
         comment: result.rows[0], // Return the added comment
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
   // Изменяем деструктуризацию, чтобы соответствовать клиентскому коду
   const { comment_id, text } = req.body;
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
      // Обновляем комментарий
      const updatedComment = await pool.query(
         "UPDATE comments SET text = $1 WHERE id = $2 RETURNING *",
         [text, comment_id]
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
      const { user_id, start_date, end_date, page = 1 } = req.query;
      const limit = 20;
      const offset = (Number(page) - 1) * limit;

      let baseQuery = `
         FROM orders o
         LEFT JOIN orders_deleted od ON o.id = od.order_id AND od.user_id = $1
         LEFT JOIN users u ON o.user_id = u.id
         WHERE od.order_id IS NULL
      `;

      let conditions = [];
      let queryParams = [user_id];

      // Фильтрация по дате (исправлено)
      if (start_date && end_date) {
         conditions.push(`o.created_at::DATE BETWEEN $${queryParams.length + 1}::DATE AND $${queryParams.length + 2}::DATE`);
         queryParams.push(start_date, end_date);
      }

      // Добавляем условия к базовому запросу
      if (conditions.length > 0) {
         baseQuery += ` AND ` + conditions.join(' AND ');
      }

      // Получаем общее количество заказов
      const countQuery = `SELECT COUNT(*) ${baseQuery}`;
      const countResult = await pool.query(countQuery, queryParams);
      const total = Number(countResult.rows[0].count);
      const totalPages = Math.ceil(total / limit);

      // Получаем заказы с лимитом
      const dataQuery = `
         SELECT o.*, u.login
         ${baseQuery}
         ORDER BY o.created_at DESC
         LIMIT ${limit} OFFSET ${offset}
      `;

      const ordersResult = await pool.query(dataQuery, queryParams);

      res.json({
         data: ordersResult.rows,
         currentPage: Number(page),
         totalPages,
      });
   } catch (err) {
      console.error('Ошибка:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.get('/get-all-order-dates', async (req, res) => {
   try {
      const { user_id } = req.query;

      // Запрос только для дат заказов без фильтрации по дате и без пагинации
      const query = `
       SELECT DISTINCT to_char(o.created_at, 'YYYY-MM-DD') as order_date
       FROM orders o
       LEFT JOIN orders_deleted od ON o.id = od.order_id AND od.user_id = $1
       WHERE od.order_id IS NULL
       ORDER BY order_date
     `;

      const result = await pool.query(query, [user_id]);

      // Извлекаем даты из результата запроса
      const dates = result.rows.map(row => row.order_date);

      res.json({ dates });
   } catch (err) {
      console.error('Ошибка при получении дат заказов:', err);
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

      // Создаем текущее время в UTC с использованием ISO строки 
      const now = new Date();
      const isoString = now.toISOString();
      const date_messages = isoString.split("T")[0]; // YYYY-MM-DD
      const time_messages = isoString.split("T")[1].split(".")[0]; // HH:MM:SS в UTC

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

app.delete("/delete-messages-global", async (req, res) => {
   try {
      const { user_id, message_ids } = req.body;

      if (!user_id || !Array.isArray(message_ids) || message_ids.length === 0) {
         return res.status(400).json({ error: 'user_id и message_ids (массив) обязательны' });
      }

      // Убираем дубликаты
      const uniqueMessageIds = [...new Set(message_ids)];

      // Проверяем, имеет ли пользователь права на удаление этих сообщений
      // (только отправитель может глобально удалить сообщение)
      const userMessagesResult = await pool.query(
         `SELECT id FROM messages 
          WHERE id = ANY($1) AND user_from_id = $2`,
         [uniqueMessageIds, user_id]
      );

      const userMessageIds = userMessagesResult.rows.map(row => row.id);

      if (userMessageIds.length === 0) {
         return res.status(403).json({ error: 'Удалять для обоих может только отправитель' });
      }

      // Физическое удаление сообщений из базы данных
      await pool.query(
         `DELETE FROM messages WHERE id = ANY($1)`,
         [userMessageIds]
      );

      // Удаляем записи из messages_deleted, так как сообщения удалены физически
      await pool.query(
         `DELETE FROM messages_deleted WHERE message_id = ANY($1)`,
         [userMessageIds]
      );

      res.json({
         success: true,
         message: "Сообщения удалены для обоих пользователей",
         deleted_messages: userMessageIds
      });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get("/get-messages", async (req, res) => {
   try {
      const { user_id, page = 1, limit = 30, filter = 'incoming' } = req.query;
      if (!user_id) {
         return res.status(400).json({ error: 'user_id обязателен' });
      }

      const offset = (page - 1) * limit;
      let whereClause;
      let countWhereClause;

      // Определяем условие WHERE в зависимости от фильтра
      if (filter === 'sent') {
         whereClause = "m.user_from_id = $1 AND d.message_id IS NULL";
         countWhereClause = "m.user_from_id = $1 AND d.message_id IS NULL";
      } else if (filter === 'unread') {
         whereClause = "m.user_to_id = $1 AND m.is_read = false AND d.message_id IS NULL";
         countWhereClause = "m.user_to_id = $1 AND m.is_read = false AND d.message_id IS NULL";
      } else { // incoming по умолчанию
         whereClause = "m.user_to_id = $1 AND d.message_id IS NULL";
         countWhereClause = "m.user_to_id = $1 AND d.message_id IS NULL";
      }

      // Запрос общего количества сообщений для пагинации с учетом фильтра
      const countResult = await pool.query(
         `SELECT COUNT(m.id)
         FROM messages m
         LEFT JOIN messages_deleted d
            ON m.id = d.message_id AND d.user_id = $1
         WHERE ${countWhereClause}`,
         [user_id]
      );

      // Запрос данных с пагинацией и фильтрацией
      const messagesResult = await pool.query(
         `SELECT m.id,
            TO_CHAR(m.date_messages, 'YYYY-MM-DD') as date_messages,
            m.time_messages, m.text_messages,
            u1.login AS sender, u2.login AS receiver,
            CASE WHEN m.user_to_id = $1 THEN m.is_read ELSE true END AS is_read
         FROM messages m
         JOIN users u1 ON m.user_from_id = u1.id
         JOIN users u2 ON m.user_to_id = u2.id
         LEFT JOIN messages_deleted d
            ON m.id = d.message_id AND d.user_id = $1
         WHERE ${whereClause}
         ORDER BY m.date_messages DESC, m.time_messages DESC
         LIMIT $2 OFFSET $3`,
         [user_id, limit, offset]
      );

      // Запрос для получения количества непрочитанных
      const unreadResult = await pool.query(
         `SELECT COUNT(*) as unread_count
         FROM messages m
         LEFT JOIN messages_deleted d
            ON m.id = d.message_id AND d.user_id = $1
         WHERE m.user_to_id = $1
         AND m.is_read = false
         AND d.message_id IS NULL`,
         [user_id]
      );

      const totalMessages = parseInt(countResult.rows[0].count, 10);
      const totalPages = Math.ceil(totalMessages / limit);
      const unreadCount = parseInt(unreadResult.rows[0].unread_count, 10);

      res.json({
         messages: messagesResult.rows,
         totalPages,
         currentPage: parseInt(page),
         unreadCount
      });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/mark-as-read", async (req, res) => {
   try {
      const { message_id, user_id } = req.body;

      if (!message_id || !user_id) {
         return res.status(400).json({ error: 'message_id и user_id обязательны' });
      }

      // Проверяем, что пользователь является получателем сообщения
      const checkResult = await pool.query(
         `SELECT * FROM messages WHERE id = $1 AND user_to_id = $2`,
         [message_id, user_id]
      );

      if (checkResult.rows.length === 0) {
         return res.status(403).json({ error: 'Доступ запрещен или сообщение не найдено' });
      }

      // Отмечаем сообщение как прочитанное
      await pool.query(
         `UPDATE messages SET is_read = true WHERE id = $1`,
         [message_id]
      );

      res.json({ success: true, message: 'Сообщение отмечено как прочитанное' });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.post("/mark-messages-read", async (req, res) => {
   try {
      const { user_id, message_ids } = req.body;

      if (!user_id || !message_ids || !Array.isArray(message_ids) || message_ids.length === 0) {
         return res.status(400).json({ error: 'user_id и message_ids (массив) обязательны' });
      }

      // Отмечаем все указанные сообщения как прочитанные
      // Но только те, где пользователь является получателем
      await pool.query(
         `UPDATE messages 
          SET is_read = true 
          WHERE id = ANY($1::int[]) AND user_to_id = $2`,
         [message_ids, user_id]
      );

      res.json({ success: true, message: 'Сообщения отмечены как прочитанные' });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get("/unread-count", async (req, res) => {
   try {
      const { user_id } = req.query;

      if (!user_id) {
         return res.status(400).json({ error: 'user_id обязателен' });
      }

      const result = await pool.query(
         `SELECT COUNT(*) as unread_count
          FROM messages m
          LEFT JOIN messages_deleted d
             ON m.id = d.message_id AND d.user_id = $1
          WHERE m.user_to_id = $1 
          AND m.is_read = false
          AND d.message_id IS NULL`,
         [user_id]
      );

      res.json({ unread_count: parseInt(result.rows[0].unread_count) });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get('/users', async (req, res) => {
   try {
      const { page = 1, login } = req.query;
      const limit = 20;
      const offset = (page - 1) * limit;

      // Базовый SQL-запрос
      let query = `
         SELECT u.id, u.login, u.avatar, u.date_of_create, u.mail, u.session_id, 
                COALESCE(r.name, '') AS role
         FROM users u
         LEFT JOIN roles r ON u.id = r.user_id
      `;
      let countQuery = `SELECT COUNT(*) FROM users`;
      let values = [];
      let countValues = [];

      // Фильтр по логину, если login передан и не пустой
      if (login && login.trim() !== '') {
         query += ` WHERE u.login ILIKE $1`;
         countQuery += ` WHERE login ILIKE $1`;
         values.push(`%${login}%`);
         countValues.push(`%${login}%`);
      }

      query += ` ORDER BY u.id LIMIT $${values.length + 1} OFFSET $${values.length + 2}`;
      values.push(limit, offset);

      const { rows: users } = await pool.query(query, values);
      const { rows } = await pool.query(countQuery, countValues);
      const totalUsers = parseInt(rows[0].count, 10);
      const totalPages = Math.ceil(totalUsers / limit);

      res.json({ users, totalPages });
   } catch (err) {
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.delete('/users-delete', async (req, res) => {
   try {
      const { userIds } = req.body;

      if (!Array.isArray(userIds) || userIds.length === 0) {
         return res.status(400).json({ error: 'Неверный формат запроса, массив userIds обязателен' });
      }

      // Удаляем пользователей с переданными ID
      const query = `DELETE FROM users WHERE id = ANY($1) RETURNING id`;

      const { rows } = await pool.query(query, [userIds]);

      res.json({ message: 'Пользователи удалены', deletedUsers: rows.map(row => row.id) });
   } catch (err) {
      console.error('Ошибка при удалении пользователей:', err);
      res.status(500).json({ error: 'Ошибка сервера', message: err.message });
   }
});

app.post('/change-user-avatar', uploadPhoto.single("photo"), async (req, res) => {
   try {
      const { id } = req.body;
      if (!req.file) {
         return res.status(400).json({ error: 'Файл не загружен' });
      }
      const photoBuffer = req.file.buffer; // Получаем бинарные данные фото
      // Обновляем поле 'avatar' в базе данных без запроса поля 'role'
      const result = await pool.query(
         `UPDATE users
          SET avatar = $1
          WHERE id = $2
          RETURNING id, login, mail, date_of_create`, // Убрано поле 'role'
         [photoBuffer, id]
      );
      if (result.rows.length === 0) {
         return res.status(404).json({ error: 'Пользователь не найден' });
      }
      // Получаем обновленные данные пользователя
      const user = result.rows[0];
      // Добавляем признак наличия аватара, но не передаем его бинарные данные
      user.avatar = { type: 'image', data: [] }; // Пустой массив как индикатор наличия аватара
      res.json(user);
   } catch (error) {
      console.error("Server error:", error);
      res.status(500).json({ error: 'Ошибка сервера', message: error.message });
   }
});

app.post('/reset-session', async (req, res) => {
   try {
      const { user_id } = req.body;

      if (!user_id) {
         return res.status(400).json({ error: "user_id обязателен" });
      }

      // Генерируем новый session_id
      const newSessionId = uuidv4();

      // Обновляем session_id в базе данных
      const query = `UPDATE users SET session_id = $1 WHERE id = $2 RETURNING id`;
      const { rows } = await pool.query(query, [newSessionId, user_id]);

      if (rows.length === 0) {
         return res.status(404).json({ error: "Пользователь не найден" });
      }

      res.json({
         message: "Сессия пользователя успешно сброшена",
         user_id: rows[0].id
      });
   } catch (err) {
      console.error("Ошибка:", err);
      res.status(500).json({ error: "Ошибка сервера", message: err.message });
   }
});

app.get('/user-avatar/:id', async (req, res) => {
   try {
      const { id } = req.params;

      const result = await pool.query(
         `SELECT avatar FROM users WHERE id = $1`,
         [id]
      );

      if (result.rows.length === 0 || !result.rows[0].avatar) {
         return res.status(404).send('Avatar not found');
      }

      // Устанавливаем правильный Content-Type для изображения
      res.set('Content-Type', 'image/jpeg');
      res.send(result.rows[0].avatar);
   } catch (error) {
      console.error("Error fetching avatar:", error);
      res.status(500).send('Server error');
   }
});

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

app.get("/check-user-session", async (req, res) => {
   try {
      const token = req.headers.authorization?.split(' ')[1];
      if (!token) {
         return res.status(401).json({ error: "Токен не предоставлен" });
      }

      try {
         // Декодируем JWT-токен
         const decoded = jwt.verify(token, JWT_SECRET);

         // Получаем актуальные данные пользователя
         const userQuery = await pool.query(`
         SELECT users.*, roles.name AS role 
         FROM users
         LEFT JOIN roles ON users.id = roles.user_id
         WHERE users.login = $1
       `, [decoded.login]);

         if (userQuery.rows.length === 0) {
            return res.status(404).json({ error: "Пользователь не найден" });
         }

         const user = userQuery.rows[0];

         // Проверяем, совпадает ли session_id из токена с session_id в базе данных
         if (decoded.sessionId !== user.session_id) {
            return res.status(401).json({ error: "Сессия устарела", sessionExpired: true });
         }

         // Возвращаем актуальные данные пользователя
         user.role = user.role || "user"; // если роли нет, ставим "user"
         res.json({ user });

      } catch (err) {
         // Если токен невалидный
         return res.status(401).json({ error: "Невалидный токен" });
      }

   } catch (err) {
      console.error("Ошибка при проверке сессии:", err);
      res.status(500).json({ error: "Ошибка сервера" });
   }
});

app.post("/upload-file", upload.single("file"), async (req, res) => {
   try {
      if (!req.file) return res.status(400).json({ error: "Файл не найден" });

      const accounts = await parseTxtFile(req.file.path);

      fs.unlinkSync(req.file.path); // Удаляем временный файл

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
            // Проверяем существование перед вставкой, избегая ON CONFLICT
            const existingCity = await pool.query("SELECT id FROM city WHERE name_ru = $1", [account.city]);
            if (existingCity.rows.length === 0) {
               let insertCity = await pool.query(
                  "INSERT INTO city (name_ru, name_eu) VALUES ($1, $2) RETURNING id",
                  [account.city, account.city]
               );
               cityId = insertCity.rows[0].id;
            } else {
               cityId = existingCity.rows[0].id;
            }
         }

         // === Определение даты рождения ===
         let dateOfBirth = null;
         if (account.dr) {
            let currentYear = new Date().getFullYear();
            let birthYear = currentYear - parseInt(account.dr, 10);
            dateOfBirth = `${birthYear}-01-01`;
         }

         // Проверяем существует ли уже аккаунт с таким identificator
         const existingAccount = await pool.query(
            "SELECT id FROM accounts WHERE identificator = $1",
            [identificator]
         );

         // Обработка даты создания для вставки в БД
         let dateToInsert;
         if (account.date_of_create === null) {
            dateToInsert = null;
         } else if (account.date_of_create && account.date_of_create.trim() !== '') {
            // Преобразуем формат YYYY.MM.DD в YYYY-MM-DD для SQL
            const dateStr = account.date_of_create.replace(/\./g, '-');


            try {
               // Для формата YYYY.MM.DD или YYYY-MM-DD
               const dateParts = dateStr.split(/[-\.]/);

               if (dateParts.length === 3) {
                  // Предполагаем формат YYYY.MM.DD
                  const [year, month, day] = dateParts;

                  // Проверяем, что все части являются числами и имеют правильную длину
                  if (/^\d{4}$/.test(year) && /^\d{1,2}$/.test(month) && /^\d{1,2}$/.test(day)) {
                     // Форматируем в YYYY-MM-DD
                     dateToInsert = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
                  } else {
                     dateToInsert = null;
                  }
               } else {
                  dateToInsert = null;
               }
            } catch (e) {
               dateToInsert = null;
            }
         } else {
            // Если дата не указана, используем текущую дату
            dateToInsert = new Date().toISOString().split('T')[0];
         }

         // Если мы дошли до этого места и dateToInsert === null, но дата была в файле,
         // попробуем еще один вариант преобразования
         if (dateToInsert === null && account.date_of_create && account.date_of_create.trim() !== '') {
            try {
               // Попробуем просто создать дату из строки
               const dateParts = account.date_of_create.split('.');
               if (dateParts.length === 3) {
                  const [year, month, day] = dateParts;
                  const numYear = parseInt(year, 10);
                  const numMonth = parseInt(month, 10);
                  const numDay = parseInt(day, 10);

                  // Простая валидация
                  if (numYear >= 1900 && numYear <= 2100 &&
                     numMonth >= 1 && numMonth <= 12 &&
                     numDay >= 1 && numDay <= 31) {
                     dateToInsert = `${numYear}-${numMonth.toString().padStart(2, '0')}-${numDay.toString().padStart(2, '0')}`;
                  }
               }
            } catch (e) {
            }
         }


         let accountId;
         if (existingAccount.rows.length > 0) {
            // Обновляем существующий аккаунт
            const updateQuery = `
               UPDATE accounts 
               SET name = $1, 
                   check_video = $2, 
                   "City_id" = $3, 
                   date_of_create = $4, 
                   date_of_birth = $5 
               WHERE identificator = $6 
               RETURNING id, date_of_create`;

            const updateResult = await pool.query(
               updateQuery,
               [
                  account.title,
                  account.nvideo === "1" ? 1 : 0,
                  cityId,
                  dateToInsert,
                  dateOfBirth,
                  identificator
               ]
            );

            accountId = updateResult.rows[0].id;
         } else {
            // Создаем новый аккаунт
            const insertQuery = `
               INSERT INTO accounts 
               (name, identificator, check_video, "City_id", date_of_create, date_of_birth) 
               VALUES ($1, $2, $3, $4, $5, $6) 
               RETURNING id, date_of_create`;

            const accountResult = await pool.query(
               insertQuery,
               [
                  account.title,
                  identificator,
                  account.nvideo === "1" ? 1 : 0,
                  cityId,
                  dateToInsert,
                  dateOfBirth
               ]
            );

            accountId = accountResult.rows[0].id;
         }

         // Проверка, что дата действительно сохранилась
         const checkResult = await pool.query(
            "SELECT date_of_create FROM accounts WHERE id = $1",
            [accountId]
         );

         console.log(`Проверка сохранения даты для аккаунта ${identificator}:`,
            checkResult.rows[0].date_of_create);

         // === Добавление тегов ===
         let tags = account.tags || "";
         tags = tags.split(",").map(tag => tag.trim()).filter(tag => tag.length > 0);

         for (const tag of tags) {
            // Проверяем существование тега
            let tagResult = await pool.query("SELECT id FROM tags WHERE name_ru = $1", [tag]);
            let tagId;

            if (tagResult.rows.length === 0) {
               // Создаем новый тег
               let insertTagResult = await pool.query(
                  "INSERT INTO tags (name_ru, name_eu) VALUES ($1, $1) RETURNING id",
                  [tag]
               );
               tagId = insertTagResult.rows[0].id;
            } else {
               tagId = tagResult.rows[0].id;
            }

            // Проверяем, существует ли уже связь между тегом и аккаунтом
            const existingTagDetail = await pool.query(
               "SELECT 1 FROM tags_detail WHERE tag_id = $1 AND account_id = $2",
               [tagId, accountId]
            );

            if (existingTagDetail.rows.length === 0) {
               // Создаем связь, только если её ещё нет
               await pool.query(
                  "INSERT INTO tags_detail (tag_id, account_id) VALUES ($1, $2)",
                  [tagId, accountId]
               );
            }
         }

         // === Создание папки для аккаунта на SFTP сервере ===
         try {
            await createDirectory(identificator);
            console.log(`Создана директория на SFTP: ${identificator}`);
         } catch (sftpError) {
            console.error(`Ошибка создания директории на SFTP для ${identificator}:`, sftpError);
            // Продолжаем выполнение, не прерывая процесс из-за ошибки с SFTP
         }

         // === Обработка социальных сетей ===
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
            tel: "tel",
            skype: "skype"
         };

         for (const [key, socialIdentificator] of Object.entries(socialTypes)) {
            // Получаем все значения для текущего типа социальной сети
            const values = account[key];

            if (!values || values.length === 0) continue;

            // Получаем id типа социальной сети
            let socialTypeResult = await pool.query(
               "SELECT id FROM socials_type WHERE identificator = $1",
               [socialIdentificator]
            );

            if (socialTypeResult.rows.length === 0) continue;

            const typeSocialId = socialTypeResult.rows[0].id;

            // Обрабатываем каждое значение для данного типа социальной сети
            for (const value of values) {
               if (!value || value.trim() === '') continue;

               // Проверяем, существует ли уже такая запись в socials
               const existingSocial = await pool.query(
                  "SELECT id FROM socials WHERE type_social_id = $1 AND text = $2",
                  [typeSocialId, value]
               );

               let socialId;

               if (existingSocial.rows.length > 0) {
                  socialId = existingSocial.rows[0].id;
               } else {
                  // Добавляем новую запись, если не существует
                  const insertSocialResult = await pool.query(
                     "INSERT INTO socials (type_social_id, text) VALUES ($1, $2) RETURNING id",
                     [typeSocialId, value]
                  );
                  socialId = insertSocialResult.rows[0].id;
               }

               // Проверяем существует ли уже связь между аккаунтом и социальной сетью
               const existingSocialDetail = await pool.query(
                  "SELECT 1 FROM socials_detail WHERE account_id = $1 AND socials_id = $2",
                  [accountId, socialId]
               );

               if (existingSocialDetail.rows.length === 0) {
                  // Создаем связь только если её еще нет
                  await pool.query(
                     "INSERT INTO socials_detail (account_id, socials_id) VALUES ($1, $2)",
                     [accountId, socialId]
                  );
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

app.post("/account-edit-media", upload.array("files"), async (req, res) => {
   try {
      const id = req.query.id;
      if (!id) {
         return res.status(400).json({ success: false, message: "Отсутствует id" });
      }

      // Создаем директорию на SFTP, если она не существует
      try {
         console.log(`Попытка создания/проверки директории ${id} на SFTP...`);
         await createDirectory(id);
         console.log(`Директория проверена/создана на SFTP: ${id}`);
      } catch (dirError) {
         console.error(`Ошибка при создании директории на SFTP для ${id}:`, dirError);
         return res.status(500).json({
            success: false,
            message: "Ошибка при работе с SFTP",
            error: dirError.message
         });
      }

      // Обрабатываем входящие ссылки
      let incomingLinks = [];
      if (req.body.links) {
         try {
            incomingLinks = JSON.parse(req.body.links);
            incomingLinks = incomingLinks.filter(item => typeof item === "string");
            console.log(`Получено ${incomingLinks.length} ссылок`);
         } catch (error) {
            console.error("Ошибка парсинга JSON:", error);
         }
      }

      // Проверяем наличие файлов
      console.log(`Количество загружаемых файлов: ${req.files ? req.files.length : 0}`);

      try {
         // Получаем файлы в папке на SFTP
         console.log(`Получение списка существующих файлов на SFTP в директории ${id}...`);
         let existingFiles = await listFiles(id);
         console.log(`Существующие файлы в директории ${id}:`, existingFiles);

         // Получаем все занятые номера
         let usedNumbers = existingFiles
            .map(file => {
               const fileNumber = parseInt(file.split(".")[0]);
               return isNaN(fileNumber) ? -1 : fileNumber;
            })
            .filter(num => num >= 0);

         console.log("Занятые номера файлов:", usedNumbers);

         // Функция для поиска первого свободного номера
         const getNextNumber = (usedNumbers, start) => {
            let number = start;
            while (usedNumbers.includes(number)) number++;
            usedNumbers.push(number); // Добавляем в занятые, чтобы избежать дублирования
            return number;
         };

         // Загружаем новые файлы на SFTP
         let uploadedFiles = [];

         if (req.files && req.files.length > 0) {
            const uploadPromises = req.files.map(async (file) => {
               try {
                  let ext = path.extname(file.originalname).toLowerCase();
                  let newNumber = /\.(mp4|mov|avi|mkv)$/i.test(ext)
                     ? getNextNumber(usedNumbers, 200)  // Видео от 200 и выше
                     : getNextNumber(usedNumbers, 1);   // Картинки от 1 до 199

                  let newFileName = `${newNumber}${ext}`;
                  console.log(`Загрузка файла ${file.originalname} как ${newFileName}...`);

                  // Загружаем файл на SFTP
                  const remotePath = await uploadFile(file.path, id, newFileName);
                  console.log(`Файл успешно загружен на SFTP: ${remotePath}`);

                  // Создаем публичную ссылку на файл
                  const publicUrl = getPublicUrl(remotePath);
                  uploadedFiles.push(publicUrl);

                  // Удаляем временный файл
                  if (fs.existsSync(file.path)) {
                     fs.unlinkSync(file.path);
                     console.log(`Временный файл ${file.path} удален`);
                  }

                  return publicUrl;
               } catch (uploadError) {
                  console.error(`Ошибка при загрузке файла ${file.originalname}:`, uploadError);
                  // Удаляем временный файл даже при ошибке
                  if (fs.existsSync(file.path)) {
                     fs.unlinkSync(file.path);
                     console.log(`Временный файл ${file.path} удален после ошибки`);
                  }
                  throw uploadError;
               }
            });

            // Ждем завершения всех загрузок
            await Promise.all(uploadPromises);
            console.log(`Загружено ${uploadedFiles.length} файлов`);
         } else {
            console.log("Нет файлов для загрузки");
         }

         // Получаем обновленный список файлов
         console.log("Получение обновленного списка файлов...");
         existingFiles = await listFiles(id);

         // Получаем имена файлов из ссылок
         let incomingFileNames = incomingLinks.map(link => path.basename(link));
         let uploadedFileNames = uploadedFiles.map(link => path.basename(link));

         console.log("Сохраняемые файлы (из ссылок):", incomingFileNames);
         console.log("Загруженные файлы:", uploadedFileNames);

         // Удаляем файлы, которых нет в incomingFileNames и uploadedFileNames
         if (incomingFileNames.length > 0 || uploadedFileNames.length > 0) {
            const filesToDelete = existingFiles.filter(file =>
               !incomingFileNames.includes(file) && !uploadedFileNames.includes(file));

            console.log("Файлы для удаления:", filesToDelete);

            const deletePromises = filesToDelete.map(async (file) => {
               try {
                  await deleteFile(`${id}/${file}`);
                  console.log(`Файл удален с SFTP: ${id}/${file}`);
               } catch (deleteError) {
                  console.error(`Ошибка при удалении файла ${file}:`, deleteError);
               }
            });

            // Ждем завершения всех удалений
            await Promise.all(deletePromises);
         } else {
            console.log("Нет файлов для удаления (сохраняем все существующие)");
         }

         // Получаем финальный список файлов и формируем публичные ссылки
         console.log("Получение финального списка файлов...");
         const updatedFiles = await listFiles(id);
         const updatedFileUrls = updatedFiles
            .filter(file => file.endsWith('.jpg') || file.endsWith('.png') || file.endsWith('.mp4'))
            .map(file => getPublicUrl(`/${id}/${file}`));

         console.log(`Финальный список файлов (${updatedFileUrls.length}):`, updatedFileUrls);

         res.json({
            success: true,
            message: "Операция выполнена успешно",
            files: updatedFileUrls,
            uploaded: uploadedFiles.length,
            deleted: existingFiles.length - updatedFiles.length + uploadedFiles.length
         });
      } catch (sftpError) {
         console.error(`Ошибка при работе с SFTP:`, sftpError);
         return res.status(500).json({
            success: false,
            message: "Ошибка при работе с SFTP",
            error: sftpError.message
         });
      }
   } catch (error) {
      console.error("Общая ошибка:", error);

      // Удаляем временные файлы при ошибке
      if (req.files && Array.isArray(req.files)) {
         for (const file of req.files) {
            if (fs.existsSync(file.path)) {
               fs.unlinkSync(file.path);
               console.log(`Временный файл ${file.path} удален при общей ошибке`);
            }
         }
      }

      res.status(500).json({
         success: false,
         message: "Ошибка на сервере",
         error: error.message
      });
   }
});

app.get('/fileBase/*', async (req, res) => {
   try {
      const filePath = req.path; // This will be "/fileBase/JD123/1.jpg"
      const sftp = await getSftpClient();

      try {
         const fullPath = path.posix.join(BASE_PATH, filePath.replace('/fileBase/', ''));
         const exists = await sftp.exists(fullPath);

         if (!exists) {
            return res.status(404).send('File not found');
         }

         // Determine content type based on file extension
         const ext = path.extname(filePath).toLowerCase();
         const contentTypes = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.mp4': 'video/mp4'
         };

         // Set appropriate content type
         res.setHeader('Content-Type', contentTypes[ext] || 'application/octet-stream');

         // Stream the file directly to the response
         const readStream = await sftp.createReadStream(fullPath);
         readStream.pipe(res);

         // Handle read stream errors
         readStream.on('error', (err) => {
            console.error(`Error streaming file ${fullPath}:`, err);
            if (!res.headersSent) {
               res.status(500).send('Error reading file');
            }
         });

         // Ensure SFTP client is released after streaming
         readStream.on('end', () => {
            releaseSftpClient(sftp);
         });
      } catch (error) {
         releaseSftpClient(sftp);
         console.error(`Error serving file ${filePath}:`, error);
         res.status(500).send('Server error');
      }
   } catch (err) {
      console.error('Error getting SFTP client:', err);
      res.status(500).send('Server error');
   }
});

app.delete("/delete-accounts", async (req, res) => {
   try {
      const { account_ids } = req.body;
      if (!Array.isArray(account_ids) || account_ids.length === 0) {
         return res.status(400).json({ error: "account_ids должен быть массивом с хотя бы одним ID" });
      }

      // Получаем идентификаторы аккаунтов перед удалением
      const result = await pool.query(
         `SELECT identificator FROM accounts WHERE id = ANY($1);`,
         [account_ids]
      );
      const account_identificators = result.rows.map(row => row.identificator);
      if (account_identificators.length === 0) {
         return res.status(404).json({ error: "Ни один аккаунт не найден" });
      }

      // Удаляем записи из базы данных
      const { rowCount } = await pool.query(`DELETE FROM accounts WHERE id = ANY($1);`, [account_ids]);

      // Удаляем папки с файлами как на локальном сервере, так и на SFTP
      const deletionPromises = account_identificators.map(async (identificator) => {
         // Удаляем папку на SFTP сервере
         try {
            await deleteRemoteDirectory(identificator);
         } catch (error) {
            console.error(`Ошибка при удалении папки на SFTP для ${identificator}:`, error);
         }

         // Удаляем локальную папку (если она существует)
         const localFolderPath = path.join(__dirname, "fileBase", identificator);
         if (fs.existsSync(localFolderPath)) {
            fs.rmSync(localFolderPath, { recursive: true, force: true });
         }
      });

      await Promise.all(deletionPromises);

      res.json({ message: `Удалено ${rowCount} аккаунтов и их файлы` });
   } catch (error) {
      console.error("Ошибка при удалении аккаунтов:", error);
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
      console.log(fs.existsSync(sectionDir));

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
               const tempFilePath = file.path; // Используем путь, который multer присвоил файлу
               const newFilePath = path.join(sectionDir, file.originalname);

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
      res.status(500).json({ error: error.message });
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

      // Важное изменение здесь: передаем null напрямую в запрос
      const result = await pool.query(
         `UPDATE accounts
          SET date_of_create = $1
          WHERE id = $2
          RETURNING *`,  // Возвращаем обновленную строку для проверки
         [new_date_of_create, id]
      );

      // Если аккаунт найден и обновлен
      if (result.rows.length > 0) {
         console.log("Обновленная запись:", result.rows[0]);
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
      const { id, name, city, tags, socials } = req.body;

      if (!id) {
         return res.status(400).json({ error: "ID аккаунта обязателен" });
      }

      await pool.query("BEGIN"); // Начинаем транзакцию

      // 1. Обновление имени аккаунта
      if (name) {
         await pool.query(`UPDATE accounts SET name = $1 WHERE id = $2`, [name, id]);
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

         await pool.query(`UPDATE accounts SET "City_id" = $1 WHERE id = $2`, [cityId, id]);
      }

      // 3. Работа с тегами
      const tagList = tags ? tags.split(",").map((t) => t.trim()) : [];

      const existingTags = await pool.query(
         `SELECT tag_id FROM tags_detail WHERE account_id = $1`,
         [id]
      );
      const existingTagIds = existingTags.rows.map(row => row.tag_id);

      const newTagIds = [];

      for (const tag of tagList) {
         let tagId;

         const tagResult = await pool.query(
            `SELECT id FROM tags WHERE name_ru = $1 OR name_eu = $1`,
            [tag]
         );

         if (tagResult.rows.length > 0) {
            tagId = tagResult.rows[0].id;
         } else {
            const newTag = await pool.query(
               `INSERT INTO tags (name_ru, name_eu) VALUES ($1, $1) RETURNING id`,
               [tag]
            );
            tagId = newTag.rows[0].id;
         }

         newTagIds.push(tagId);

         const tagDetailResult = await pool.query(
            `SELECT id FROM tags_detail WHERE tag_id = $1 AND account_id = $2`,
            [tagId, id]
         );

         if (tagDetailResult.rows.length === 0) {
            await pool.query(
               `INSERT INTO tags_detail (tag_id, account_id) VALUES ($1, $2)`,
               [tagId, id]
            );
         }
      }

      const tagsToRemove = existingTagIds.filter(tagId => !newTagIds.includes(tagId));

      if (tagsToRemove.length > 0) {
         await pool.query(
            `DELETE FROM tags_detail WHERE account_id = $1 AND tag_id = ANY($2)`,
            [id, tagsToRemove]
         );
      }

      // 4. Работа с соцсетями: удаление старых, добавление новых
      await pool.query(`DELETE FROM socials_detail WHERE account_id = $1`, [id]);

      for (const social of socials) {
         const { type_social_id, text } = social;

         if (!type_social_id || !text) {
            continue; // Пропускаем добавление, если нет данных
         }

         let socialResult = await pool.query(
            `SELECT id FROM socials WHERE type_social_id = $1 AND text = $2`,
            [type_social_id, text]
         );

         let socialId;

         if (socialResult.rows.length > 0) {
            socialId = socialResult.rows[0].id;
         } else {
            const newSocial = await pool.query(
               `INSERT INTO socials (type_social_id, text) VALUES ($1, $2) RETURNING id`,
               [type_social_id, text]
            );
            socialId = newSocial.rows[0].id;
         }

         await pool.query(
            `INSERT INTO socials_detail (account_id, socials_id) VALUES ($1, $2)`,
            [id, socialId]
         );
      }

      await pool.query("COMMIT");

      res.json({ message: "Аккаунт успешно обновлен" });
   } catch (err) {
      await pool.query("ROLLBACK");
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