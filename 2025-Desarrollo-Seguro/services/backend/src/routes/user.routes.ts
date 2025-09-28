
import { Router } from 'express';
import routes from '../controllers/authController';
import authMiddleware from '../middleware/auth.middleware';

const router = Router();


// Vulnerable: rutas sin autenticación
// router.post('/', routes.createUser);
// router.put('/:id', routes.updateUser);

// Mitigación: proteger rutas con autenticación
router.post('/', authMiddleware, routes.createUser);
router.put('/:id', authMiddleware, routes.updateUser);




//router.get('/:id/picture', routes.getUser);
//router.post('/:id/picture', routes.getUser);
//router.delete('/:id/picture', routes.getUser);


export default router;
