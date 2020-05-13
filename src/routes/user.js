import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user';
import { secretkey } from '../config/keys';

const router = express.Router();

router.get('/login', (req, res) => {
    /*
    TODO - 
        ADD A CHECK FOR THE CASE WHEN AUTH HAS FAILED AND 
        USER HAS BEEN REDIRECTED TO THE LOGIN PAGE
        PERHAPS PASS THE CORRESPONDING ERROR MESSAGE AND THEN RENDER PAGE
        OR THE URL QUERY CONTAINS THE SERVICE URL, YOU COULD REDIRECT TO THAT
    */

    // make sure serviceURL already has `http://` prepended
    // this is the responsibility of the client server.
    const { serviceURL } = req.query;

    // We should pass the service URL as well to the login page.
    // we pass the error handeling data to page
    res.render('login', { message: '', error: false, serviceURL });
});

router.get('/register', (req, res) => {
    res.render('register', { message: '', error: false });
});

router.post('/login', async (req, res, next) => {
    try {
        const { email, password, serviceURL } = req.body;

        // try to find the user in the database
        const user = await User.findOne({ email });

        // this means user doesn't exists, so throw an error TODO: add correct status to return
        if (!user) {
            return res.render('login', {
                message: 'Not a registered email address',
                error: true,
                serviceURL,
            });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);

        // Incorrect password
        if (!isMatch) {
            return res.render('login', {
                message: 'Password seems to be incorrect',
                error: true,
                serviceURL,
            });
        }

        // Create payload to create a token
        const payload = {
            user: {
                id: user._id,
                email: user.email,
                firstname: user.firstname,
                lastname: user.lastname,
                username: user.username,
            },
        };

        // create a token
        const token = jwt.sign(payload, secretkey, {
            expiresIn: 60 * 10,
        });

        // now build a service URL so that
        let finalServiceURL = null;

        // only build finalService URL if service URL was present.
        if (serviceURL) {
            finalServiceURL = `${serviceURL}&token=${token}`;
        }

        // render homepage to store token and then redirect to finalServiceURL if possible
        res.render('index', { token, serviceURL: finalServiceURL });
    } catch (err) {
        next(err);
    }
});

router.post('/register', async (req, res) => {
    const { firstname, lastname, username, email, password } = req.body;

    // TODO: ADD A USERNAME CHECK AS WELL, THAT ALSO HAS TO BE UNIQUE
    try {
        // try to find the user in the database
        let user = await User.findOne({ email });

        // User already exists
        if (user) {
            return res.render('register', {
                message: 'User already exists with same email',
                error: true,
            });
        }

        // Create a new user of type `User`
        user = new User({
            firstname,
            lastname,
            username,
            email,
            password,
        });

        // encrypt the password using bcrypt
        const salt = await bcrypt.genSalt(10); // which to use 10 or more than that

        // update the password to encrypted one
        user.password = await bcrypt.hash(user.password, salt);

        // Save the updated the user in database
        await user.save();

        // Create payload to create a token
        const payload = {
            user: {
                id: user._id,
                email: user.email,
                firstname: user.firstname,
                lastname: user.lastname,
                username: user.username,
            },
        };

        // create a token
        const token = jwt.sign(payload, secretkey, {
            expiresIn: 60 * 10,
        });

        // Return the token
        return res.status(200).json({ token });
    } catch (err) {
        console.log(err);
    }
});

export default router;
