export async function getWeatherData() {
    const response = await fetch('api/weatherforecast');
    return response.json();
}