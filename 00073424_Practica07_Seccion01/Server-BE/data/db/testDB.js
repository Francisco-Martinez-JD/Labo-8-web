import { pool } from "./connection";

async function test () {
    const res = await pool.query('SELECT NOW()');
    console.log(res.rows);
}

test();