import swaggerUi from 'swagger-ui-express';
import swaggerJSDoc from 'swagger-jsdoc';

import dotenv from 'dotenv';
dotenv.config();

const swaggerDefinition = {
  openapi: '3.0.0',
  info: {
    title: 'Licensing Server API',
    version: '1.0.0',
    description: 'API documentation for the licensing server with mTLS authentication.'
  },
  servers: [
    {
      url: process.env.LICENSE_SERVER_URL || 'https://localhost:8443',
      description: 'Development server'
    }
  ]
};

const swaggerOptions = {
  swaggerDefinition,
  apis: ['./routes.js'],
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

export function setupSwagger(app) {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}
