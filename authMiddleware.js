import pool from './server.js'
import jwt from 'jsonwebtoken'

const authMiddleware = async (req, res, next) => {
   const token = req.header("Authorization")?.split(" ")[1];
   const isAuth = req.header("IsAuth")

   if (!isAuth) {
      return next();
   }

   if (!token) {
      return res.status(401).json({ message: "Нет доступа" });
   }

   try {
      // Декодируем токен
      const decoded = jwt.verify(token, process.env.JWT_SECRET || "your_secret_key");

      // Получаем пользователя из БД по `login`
      const user = await pool.query("SELECT * FROM users WHERE login = $1", [decoded.login]);

      if (user.rows.length === 0) {
         return res.status(401).json({ message: "Пользователь не найден" });
      }

      // Проверяем, что session_id токена совпадает с тем, что хранится в базе данных
      if (user.rows[0].session_id !== decoded.sessionId) {
         return res.status(401).json({ message: "Ваша сессия была завершена на другом устройстве." });
      }

      req.user = user.rows[0];  // Добавляем пользователя в `req.user`
      next();
   } catch (error) {
      return res.status(401).json({ message: "Ошибка авторизации" });
   }
};

export default authMiddleware;