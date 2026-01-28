import express from "express";
import router from "./routes/index.js";
import { globalErrorHandler } from "./middlewares/error-handler.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/api/v1/", router);

app.use(globalErrorHandler);

export default app;
