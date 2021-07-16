import redis from 'redis';

const rtokens = redis.createClient();

rtokens.on('error', (err) => {
    console.log(err);
});

export default rtokens;
