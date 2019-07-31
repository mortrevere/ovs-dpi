
function cleanData(chart) {
    chart.data.labels = []
    chart.data.datasets[0].data = []
    chart.update();
}

function loadData(chart, labels, data) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.data.datasets[0].backgroundColor = palette('tol-dv', labels.length).map(function (hex) {
        return '#' + hex;
    })
    chart.update();
}


/*
totalVolume = data.data.reduce((prev, next) => {
    return prev + next;
}, 0);

ignored = {}
data.data.forEach((volume, i) => {
    if(volume*100/totalVolume < .5) {
        ignored[i] = true;
    }
})
ignoredVolume = 0
data.data = data.data.filter((volume, i) => {
    if(ignored[i]) ignoredVolume += volume;
    return !ignored[i];
});
data.labels = data.labels.filter((volume, i) => !ignored[i]);
data.labels.push('Others');
data.data.push(ignoredVolume)
*/

var charts_id = ['http', 'https'/*, 'dns'*/]
var charts = charts_id

window.onload = () => {
    charts = charts.map(chart_id => {
        return new Chart(document.getElementById("doughnut-chart-" + chart_id), {
            type: 'doughnut',
            data: {
                labels: ['Loading ...'],
                datasets: [
                    {
                        label: "Domains",
                        backgroundColor: palette('tol-dv', 1).map(function (hex) {
                            return '#' + hex;
                        }),
                        data: [1]
                    }
                ]
            },
            options: {
                title: {
                    display: true,
                    text: 'Live DPI data (' + chart_id + ')'
                }
            }
        });
    });

    function updateGraph() {
        charts_id.forEach((chart_id, i) => {
            console.log(chart_id, i);
            fetch('http://10.206.19.154:9000/' + chart_id).then(response => {
                return response.json().then(dpi_data => {
                    loadData(charts[i], dpi_data.labels, dpi_data.data);
                });
            });
        });
    }
    setInterval(updateGraph, 3000)
}