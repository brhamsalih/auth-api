import express  from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import Jwt  from 'jsonwebtoken';
import { body, validationResult} from 'express-validator';
const app = express()

const secretKey = 'aaaf28893d7350af917bc8ebab4ad922199b1314bac9254ad247714886fadb01'; 
app.use(bodyParser.json())

//In memory user storge
const users = [];


// Validation middleware
const validateUser = [
    body('username').notEmpty().withMessage('Username is required').custom(value => {
      const existingUser = users.find(user => user.username === value);
      if (existingUser) {
        throw new Error('Username is already in use');
      }
      return true;
    }),
  
    body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Invalid email').custom(value => {
      const existingEmail = users.find(user => user.email === value);
      if (existingEmail) {
        throw new Error('Email is already in use');
      }
      return true;
    }),
  
    body('password')
      .notEmpty().withMessage('Password is required')
      .isStrongPassword().withMessage('Password should be at least 8 characters long and include upper and lower case letters, a number, and a special character'),
  ];
  
//authenticate JWT
function authenticateToken(req, res, next) {
    const token = req.header('Authorization');
  
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
    Jwt.verify(token, secretKey, (err, users) => {
      if (err) return res.status(403).json({ error: 'Forbidden' });
  
      req.users = users;
      next();
    });
  }
// Password recovery initiation
app.post('/recover', (req, res) => {
    const { email } = req.body;
    const user = users.find((data) => data.email === email);

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
  // Generate a recovery token (for simplicity, using the user's ID)
    const recoveryToken = Jwt.sign({ userId: user.id }, secretKey, { expiresIn: '1h' });

    res.json({ message: 'Recovery email sent successfully', recoveryToken });   
});

//---------------------------------------------------------------------------------------------------//

//Register endpoint
app.post('/register',validateUser, async (req, res) => {
    try{
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
          }
          // Add the user to the database 
          const hashPassword = await bcrypt.hash(req.body.password, 10)
          const newUser = {
            id: users.length + 1,
            username: req.body.username,
            email: req.body.email,
            password: hashPassword,
          };
        
          users.push(newUser);
        
          res.json({ message: 'User registered successfully', user: newUser });
    }catch (err){
        res.status(500).send({message: err.message});
        return
    }
    
});

//Login endpoint
app.post('/login', async (req, res) => {
    try{
        const {username, password}  = req.body;
        const finduser = users.find((data) => data.username === username)
        if (!username || !password){
            res.status(400).json({message: 'Username and password are required'})
            return
        }
        if (!finduser) {
            res.status(400).json({message: 'Wrong username or password!'});
            return
        }
        const passwordMath = await bcrypt.compare(password, finduser.password)
        if (passwordMath) {
            // Generate a JWT
            const token = Jwt.sign({ userId: finduser.id, username: finduser.username }, secretKey, { expiresIn: '1h' });
            res.status(201).json({
                message: 'Login successfuly',
                token: token
            });

        }else{
            res.status(400).json({message: 'Wrong username or password!'});
            return
        }
    }catch (err){
        res.status(500).send({message: err.message});
        return
    }
})

// Protected route that requires a valid JWT
app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route' });
  });



// Password reset route
app.put('/reset-password', async(req, res) => {
    try{
        const { recoveryToken, newPassword } = req.body;
        // Verify the recovery token
        Jwt.verify(recoveryToken, secretKey, async (err, decoded) => {
          if (err) {
            return res.status(401).json({ error: 'Invalid or expired recovery token' });
          }
          const password = await bcrypt.hash(newPassword, 10)
          const user = users.find((data) => data.id === decoded.userId);
          // Update the user's password

          return res.status(200).json({ message: 'Password reset successfully', user: user});
        });
    }catch (err){
        res.status(500).send({message: err.message});
        return
    } 
  });
// Handle 404 Not Found
app.use((req, res) => {
    res.status(404).json({ error: 'Not Found' });
  });
  
  // Handle errors
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal Server Error' });
  });

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});