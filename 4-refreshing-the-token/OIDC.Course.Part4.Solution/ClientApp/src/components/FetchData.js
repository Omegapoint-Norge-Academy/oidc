import React, {useEffect, useState} from 'react';
import { getWeatherData } from './weatherService.js'

export function FetchData() {
    const [forecasts, setForecasts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [unauthorized, setUnauthorized] = useState(false);
    
    useEffect(() => {
        getWeatherData()
            .then(response => {
                setForecasts(response);
                setLoading(false);
                setUnauthorized(false);
            })
            .catch(e => {
                setLoading(false);
                setUnauthorized(true);
            })
    }, []);

    let content;
    
    if (loading) {
        content = <p><em>Loading...</em></p>;
    }
    else if (unauthorized) {
        content = <p><em>Not authorized</em></p>;
    }
    else {
        content = (
            <table className="table table-striped" aria-labelledby="tableLabel">
                <thead>
                <tr>
                    <th>Date</th>
                    <th>Temp. (C)</th>
                    <th>Temp. (F)</th>
                    <th>Summary</th>
                </tr>
                </thead>
                <tbody>
                {forecasts.map(forecast =>
                    <tr key={forecast.date}>
                        <td>{forecast.date}</td>
                        <td>{forecast.temperatureC}</td>
                        <td>{forecast.temperatureF}</td>
                        <td>{forecast.summary}</td>
                    </tr>
                )}
                </tbody>
            </table>
        );
    }

    return (
        <div>
            <h1 id="tableLabel">Weather forecast</h1>
            <p>This component demonstrates fetching data from the server.</p>
            {content}
        </div>
    );
};
