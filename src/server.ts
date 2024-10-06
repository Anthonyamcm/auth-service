import app from './app';
import Logger from './utils/logger';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  Logger.info(`Authentication Service running on port ${PORT}`);
});
