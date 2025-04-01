import SftpClient from 'ssh2-sftp-client';
import path from 'path';
import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

const sftpConfig = {
   host: process.env.SFTP_HOST,
   port: parseInt(process.env.SFTP_PORT) || 22,
   username: process.env.SFTP_USERNAME,
   password: process.env.SFTP_PASSWORD,
   readyTimeout: 15000,        // Увеличенный таймаут подключения
   retries: 5,                 // Больше попыток переподключения
   retry_factor: 2,
   retry_minTimeout: 1000
};

const BASE_PATH = process.env.SFTP_BASE_PATH || '/fileBase';
let sftpPool = [];
const MAX_POOL_SIZE = 5;      // Увеличиваем размер пула

// Функция для логирования SFTP-операций
function logSftp(operation, message) {
   console.log(`[SFTP ${operation}] ${message}`);
}

async function getSftpClient() {
   // Сначала проверим, есть ли свободные клиенты в пуле
   for (const client of sftpPool) {
      if (!client.busy) {
         client.busy = true;
         client.lastUsed = Date.now();
         logSftp('pool', `Получен существующий клиент из пула. Активных клиентов: ${sftpPool.length}`);
         return client.sftp;
      }
   }

   // Если все клиенты заняты, но пул не заполнен, создаем новый
   if (sftpPool.length < MAX_POOL_SIZE) {
      logSftp('connect', `Создание нового SFTP-соединения...`);
      const sftp = new SftpClient();
      try {
         await sftp.connect(sftpConfig);
         logSftp('connect', `SFTP-соединение успешно установлено`);
         const poolEntry = { sftp, busy: true, created: Date.now(), lastUsed: Date.now() };
         sftpPool.push(poolEntry);
         return sftp;
      } catch (error) {
         logSftp('error', `Ошибка подключения SFTP: ${error.message}`);
         throw error;
      }
   }

   // Если нет свободных клиентов и пул заполнен, ждем освобождения
   logSftp('wait', `Ожидание освобождения SFTP-клиента в пуле...`);
   return new Promise((resolve, reject) => {
      const checkPool = setInterval(() => {
         for (const client of sftpPool) {
            if (!client.busy) {
               clearInterval(checkPool);
               client.busy = true;
               client.lastUsed = Date.now();
               logSftp('pool', `Клиент освободился и получен из пула`);
               resolve(client.sftp);
               return;
            }
         }
      }, 100);

      // Увеличиваем таймаут ожидания
      setTimeout(() => {
         clearInterval(checkPool);
         logSftp('error', `Тайм-аут ожидания SFTP-соединения`);
         reject(new Error('Тайм-аут ожидания SFTP-соединения'));
      }, 10000); // 10 секунд
   });
}

function releaseSftpClient(sftp) {
   for (const client of sftpPool) {
      if (client.sftp === sftp) {
         client.busy = false;
         client.lastUsed = Date.now();
         logSftp('pool', `SFTP-клиент освобожден. Свободных клиентов: ${sftpPool.filter(c => !c.busy).length}`);
         return;
      }
   }
}

async function createDirectory(dirPath) {
   logSftp('mkdir', `Создание директории: ${dirPath}`);
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, dirPath);
      logSftp('mkdir', `Полный путь: ${fullPath}`);

      const dirExists = await sftp.exists(fullPath);
      if (!dirExists) {
         logSftp('mkdir', `Директория не существует, создаем: ${fullPath}`);
         await sftp.mkdir(fullPath, true);
         logSftp('mkdir', `Директория успешно создана: ${fullPath}`);
      } else {
         logSftp('mkdir', `Директория уже существует: ${fullPath}`);
      }
      return fullPath;
   } catch (error) {
      logSftp('error', `Ошибка создания директории ${dirPath}: ${error.message}`);
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function exists(remotePath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, remotePath);
      const exists = await sftp.exists(fullPath);
      logSftp('exists', `Проверка существования ${fullPath}: ${exists ? 'существует' : 'не существует'}`);
      return exists;
   } catch (error) {
      logSftp('error', `Ошибка проверки существования ${remotePath}: ${error.message}`);
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function listFiles(dirPath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, dirPath);
      logSftp('list', `Получение списка файлов из: ${fullPath}`);

      if (!(await sftp.exists(fullPath))) {
         logSftp('list', `Директория не существует: ${fullPath}`);
         return [];
      }

      const files = await sftp.list(fullPath);
      const fileNames = files.filter(item => item.type === '-').map(item => item.name);
      logSftp('list', `Найдено файлов в ${fullPath}: ${fileNames.length}`);
      return fileNames;
   } catch (error) {
      logSftp('error', `Ошибка получения списка файлов из ${dirPath}: ${error.message}`);
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function uploadFile(localPath, remoteDirPath, newFileName) {
   const sftp = await getSftpClient();
   try {
      const fullRemoteDirPath = path.posix.join(BASE_PATH, remoteDirPath);
      logSftp('upload', `Загрузка файла ${localPath} в ${fullRemoteDirPath}/${newFileName}`);

      // Проверяем существование и размер локального файла
      if (!fs.existsSync(localPath)) {
         throw new Error(`Локальный файл не существует: ${localPath}`);
      }
      const stats = fs.statSync(localPath);
      logSftp('upload', `Размер локального файла: ${stats.size} байт`);

      // Проверяем и создаем удаленную директорию, если нужно
      if (!(await sftp.exists(fullRemoteDirPath))) {
         logSftp('upload', `Создание директории для загрузки: ${fullRemoteDirPath}`);
         await sftp.mkdir(fullRemoteDirPath, true);
      }

      const fullRemotePath = path.posix.join(fullRemoteDirPath, newFileName);

      // Загружаем файл с отслеживанием прогресса для больших файлов
      const readStream = fs.createReadStream(localPath);
      await sftp.put(readStream, fullRemotePath);

      // Проверяем загруженный файл
      const remoteExists = await sftp.exists(fullRemotePath);
      if (!remoteExists) {
         throw new Error(`Файл не был загружен: ${fullRemotePath}`);
      }

      logSftp('upload', `Файл успешно загружен: ${fullRemotePath}`);
      return path.posix.join(remoteDirPath, newFileName);
   } catch (error) {
      logSftp('error', `Ошибка загрузки файла ${localPath}: ${error.message}`);
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

async function deleteFile(remotePath) {
   const sftp = await getSftpClient();
   try {
      const fullPath = path.posix.join(BASE_PATH, remotePath);
      logSftp('delete', `Удаление файла: ${fullPath}`);

      if (await sftp.exists(fullPath)) {
         await sftp.delete(fullPath);
         logSftp('delete', `Файл успешно удален: ${fullPath}`);
      } else {
         logSftp('delete', `Файл не существует: ${fullPath}`);
      }
   } catch (error) {
      logSftp('error', `Ошибка удаления файла ${remotePath}: ${error.message}`);
      throw error;
   } finally {
      releaseSftpClient(sftp);
   }
}

function getPublicUrl(remotePath) {
   // Убеждаемся, что путь начинается с / и не содержит BASE_PATH
   const normalizedPath = remotePath.startsWith('/') ? remotePath : `/${remotePath}`;
   const BASE_URL = process.env.FILE_SERVER_URL || 'https://files.yourdomain.com';

   // Удаляем дублирующиеся /fileBase, если они есть в пути
   let publicPath = normalizedPath;
   if (BASE_PATH === '/fileBase' && normalizedPath.startsWith('/fileBase')) {
      publicPath = normalizedPath;
   } else {
      publicPath = path.posix.join(BASE_PATH, normalizedPath);
   }

   const url = `${BASE_URL}${publicPath}`;
   logSftp('url', `Сформирован URL: ${url} из пути ${remotePath}`);
   return url;
}

function cleanupConnections() {
   const now = Date.now();
   const MAX_IDLE_TIME = 120000; // 2 минуты (увеличено)
   const initialCount = sftpPool.length;

   sftpPool = sftpPool.filter(client => {
      if (!client.busy && client.lastUsed && now - client.lastUsed > MAX_IDLE_TIME) {
         logSftp('cleanup', `Закрытие неиспользуемого SFTP-соединения (${Math.round((now - client.lastUsed) / 1000)}с простоя)`);
         client.sftp.end().catch(err => {
            logSftp('error', `Ошибка закрытия SFTP-соединения: ${err.message}`);
         });
         return false;
      }
      return true;
   });

   if (initialCount !== sftpPool.length) {
      logSftp('cleanup', `Очистка пула: было ${initialCount}, стало ${sftpPool.length}`);
   }
}

// Проверяем подключения раз в 30 секунд
setInterval(cleanupConnections, 30000);

// Корректно закрываем все соединения при завершении приложения
process.on('SIGINT', async () => {
   logSftp('shutdown', 'Закрытие всех SFTP-соединений...');
   for (const client of sftpPool) {
      try {
         await client.sftp.end();
      } catch (error) {
         logSftp('error', `Ошибка закрытия SFTP-соединения: ${error.message}`);
      }
   }
   process.exit(0);
});

// Добавляем функцию для тестирования соединения
async function testConnection() {
   logSftp('test', 'Проверка SFTP-соединения...');
   const sftp = await getSftpClient();
   try {
      await sftp.list(BASE_PATH);
      logSftp('test', 'SFTP-соединение работает корректно');
      return true;
   } catch (error) {
      logSftp('error', `Ошибка проверки SFTP-соединения: ${error.message}`);
      return false;
   } finally {
      releaseSftpClient(sftp);
   }
}

export {
   createDirectory,
   exists,
   listFiles,
   uploadFile,
   deleteFile,
   getPublicUrl,
   testConnection,
   getSftpClient,
   releaseSftpClient
};