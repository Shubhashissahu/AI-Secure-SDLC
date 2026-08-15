import { Router } from "express";
import { createRepository, listRepositories, getRepository, updateRepository, deleteRepository } from "../controllers/repositoryController";

const router = Router();

router.post("/", createRepository);
router.get("/", listRepositories);
router.get("/:id", getRepository);
router.patch("/:id", updateRepository);
router.delete("/:id", deleteRepository);

export default router;