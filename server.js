const {app}= require('./index');
const db_access = require('./db.js');
const db = db_access.db;

db.serialize(() => {
 db.run(db_access.createTripTable, (err) => {
    if (err) console.log('Error creating trip table:', err.message);
 });

});


const PORT=3000;
app.listen(PORT,()=>{
    console.log(`Server is running on port ${PORT}`);
});

