// ESTRUCTURA COMPLETA DEL BACKEND PARA UN RESTAURANTE
// Librerías requeridas
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const SECRET = "mipasswordultrasecreto"; // puedes poner esto en .env

// Middleware para verificar token JWT
tokenAuth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Token inválido' });
  }
};

// Middleware para autorizar solo admin
soloAdmin = (req, res, next) => {
  if (req.user.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  next();
};

// Login de usuario
app.post('/api/login', async (req, res) => {
  const { correo, contrasena } = req.body;
  const usuario = await prisma.usuarios.findUnique({ where: { correo } });
  if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

  const esValido = await bcrypt.compare(contrasena, usuario.contrasena);
  if (!esValido) return res.status(401).json({ error: 'Contraseña incorrecta' });

  const token = jwt.sign({ id: usuario.id, rol: usuario.rol }, SECRET, { expiresIn: '2h' });
  res.json({ token, usuario: { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol } });
});

// Registro de cliente
app.post('/api/registro', async (req, res) => {
  const { nombre, correo, contrasena } = req.body;
  const existe = await prisma.usuarios.findUnique({ where: { correo } });
  if (existe) return res.status(400).json({ error: 'Correo ya registrado' });

  const hash = await bcrypt.hash(contrasena, 10);
  const nuevo = await prisma.usuarios.create({
    data: { nombre, correo, contrasena: hash, rol: 'cliente' }
  });
  res.status(201).json({ mensaje: 'Usuario registrado' });
});

// Obtener productos (todos)
app.get('/api/productos', async (req, res) => {
  const productos = await prisma.productos.findMany();
  res.json(productos);
});

// Crear producto (solo admin)
app.post('/api/productos', tokenAuth, soloAdmin, async (req, res) => {
  const producto = await prisma.productos.create({ data: req.body });
  res.status(201).json(producto);
});

// Editar producto
app.put('/api/productos/:id', tokenAuth, soloAdmin, async (req, res) => {
  const { id } = req.params;
  const editado = await prisma.productos.update({
    where: { id: Number(id) },
    data: req.body
  });
  res.json(editado);
});

// Eliminar producto
app.delete('/api/productos/:id', tokenAuth, soloAdmin, async (req, res) => {
  const { id } = req.params;
  await prisma.productos.delete({ where: { id: Number(id) } });
  res.json({ mensaje: 'Producto eliminado' });
});

// Obtener categorías
app.get('/api/categorias', async (req, res) => {
  const categorias = await prisma.categorias.findMany();
  res.json(categorias);
});

// Crear reserva
app.post('/api/reservas', tokenAuth, async (req, res) => {
  const { usuario_id, mesa_id, fecha_reserva } = req.body;
  const reserva = await prisma.reservas.create({
    data: {
      usuario_id,
      mesa_id,
      fecha_reserva,
      estado: 'pendiente'
    }
  });
  res.status(201).json(reserva);
});

// Crear pedido
app.post('/api/pedidos', tokenAuth, async (req, res) => {
  const { productos, total } = req.body;
  const pedido = await prisma.pedidos.create({
    data: {
      usuario_id: req.user.id,
      total,
      estado: 'pendiente',
      detalle_pedido: {
        create: productos.map(p => ({
          producto_id: p.id,
          cantidad: p.cantidad,
          subtotal: p.subtotal
        }))
      }
    },
    include: { detalle_pedido: true }
  });
  res.status(201).json(pedido);
});

// Crear pago
app.post('/api/pagos', tokenAuth, async (req, res) => {
  const { pedido_id, metodo, estado } = req.body;
  const pago = await prisma.pagos.create({
    data: {
      pedido_id,
      metodo,
      estado
    }
  });
  res.status(201).json(pago);
});

module.exports = app;
