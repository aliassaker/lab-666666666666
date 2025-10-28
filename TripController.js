// const {
//     trips
// } = require('../model/Trip');

const db_access = require('../db.js');
const db = db_access.db;

// Create a new trip
const createTrip = (req,res) => {

    const {
        destinationName,
        location,
        continent,
        language,
        description,
        flightCost,
        accommodationCost = 0,
        mealCost = 0,
        visaCost = 0,
        transportationCost = 0,
        currencyCode = 'N/A',
    }= req.body;

if(!destinationName||!location||!continent||!language||!description)
{
return res.status(400).json({
    message:"All fields are required to be filled"});
}

const query = `INSERT INTO TRIP (DESTINATIONNAME, LOCATION,
CONTINENT, LANGUAGE, DESCRIPTION, FLIGHTCOST, ACCOMMODATIONCOST, MEALCOST,
VISACOST, TRANSPORTATIONCOST, CURRENCYCODE) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

db.run(
    query,
    [destinationName, location, continent,
        language, description, flightCost, accommodationCost, 
        mealCost, visaCost, transportationCost, currencyCode],
    function (err) {
        if (err) {
            console.log(err);
            return res.status(500).json({ message: 'Error retrieving trips'});
        }
        res.status(201).json({ message: 'Trip successfully created'});
    }
)};

const retrieveAllTrips = (req, res) => {
    db.all('SELECT * FROM TRIP', (err, rows) => {
        if (err) {
            console.log(err);
            return res.status(500).json({ message: 'Error retrieving trips' });
        }
        res.status(200).json({ message: 'Trips retrieved successfully', data: rows });
    });
};

module.exports = {
    createTrip,
    retrieveAllTrips
};
