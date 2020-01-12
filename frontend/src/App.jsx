import React, {Component} from 'react';

class App extends Component {

    state = {};

    componentDidMount() {
        setInterval(this.hello, 1000);
    }

    hello = () => {
        fetch('/api/hello')
            .then(response => response.text())
            .then(message => {
                this.setState({message: message});
            });
    };

    render() {
        return (
            <div>
                <h1>{this.state.message}</h1>
            </div>
        );
    }
}

export default App;
