const express= require('express');
const {
    createTrip,
    retrieveAllTrips,
} = require('../controllers/TripController');
const tripRouter = express.Router();

tripRouter
.route('/')
.post(createTrip)
.get(retrieveAllTrips);


module.exports = tripRouter;

