async function bootstrap() {

  const app =
  await NestFactory.create(
    AppModule,
  );

  app.use(helmet());

  app.enableCors();

  app.useGlobalFilters(
    new AllExceptionFilter(),
  );

  await app.listen(3000);
}