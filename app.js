const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Multer setup for file upload handling
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function(req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Serve static files (e.g., images)
app.use('/uploads', express.static('uploads'));

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mock database (replace with actual database usage)
let books = [];

// Routes
app.get('/api/books', (req, res) => {
    res.json(books);
});

app.post('/api/books', upload.single('image'), (req, res) => {
    const { title, author, description } = req.body;
    const imagePath = req.file.path;

    const newBook = {
        id: uuidv4(),
        title,
        author,
        description,
        imagePath: imagePath.replace(/\\/g, '/').replace('uploads/', '/uploads/')
    };

    books.push(newBook);
    res.status(201).json({ message: 'Book added successfully', book: newBook });
});

app.delete('/api/books/:id', (req, res) => {
    const { id } = req.params;
    const index = books.findIndex(book => book.id === id);

    if (index !== -1) {
        const deletedBook = books.splice(index, 1);
        // Delete image file if needed: fs.unlinkSync(deletedBook[0].imagePath);
        res.json({ message: 'Book deleted successfully', book: deletedBook });
    } else {
        res.status(404).json({ message: 'Book not found' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
