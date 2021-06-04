(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],2:[function(require,module,exports){
(function (process){
'use strict';

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _reactDom = require('react-dom');

var _redux = require('redux');

var _reactRedux = require('react-redux');

var _reduxThunk = require('redux-thunk');

var _reduxThunk2 = _interopRequireDefault(_reduxThunk);

var _ProxyApp = require('./components/ProxyApp');

var _ProxyApp2 = _interopRequireDefault(_ProxyApp);

var _index = require('./ducks/index');

var _index2 = _interopRequireDefault(_index);

var _eventLog = require('./ducks/eventLog');

var _urlState = require('./urlState');

var _urlState2 = _interopRequireDefault(_urlState);

var _websocket = require('./backends/websocket');

var _websocket2 = _interopRequireDefault(_websocket);

var _static = require('./backends/static');

var _static2 = _interopRequireDefault(_static);

var _reduxLogger = require('redux-logger');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var middlewares = [_reduxThunk2.default];

if (process.env.NODE_ENV !== 'production') {
    middlewares.push(_reduxLogger.logger);
}

// logger must be last
var store = (0, _redux.createStore)(_index2.default, _redux.applyMiddleware.apply(undefined, middlewares));

(0, _urlState2.default)(store);
if (MITMWEB_STATIC) {
    window.backend = new _static2.default(store);
} else {
    window.backend = new _websocket2.default(store);
}

window.addEventListener('error', function (msg) {
    store.dispatch((0, _eventLog.add)(msg));
});

document.addEventListener('DOMContentLoaded', function () {
    (0, _reactDom.render)(_react2.default.createElement(
        _reactRedux.Provider,
        { store: store },
        _react2.default.createElement(_ProxyApp2.default, null)
    ), document.getElementById("mitmproxy"));
});

}).call(this,require('_process'))

},{"./backends/static":3,"./backends/websocket":4,"./components/ProxyApp":43,"./ducks/eventLog":56,"./ducks/index":58,"./urlState":70,"_process":1,"react":"react","react-dom":"react-dom","react-redux":"react-redux","redux":"redux","redux-logger":"redux-logger","redux-thunk":"redux-thunk"}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /*
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * This backend uses the REST API only to host static instances,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      * without any Websocket connection.
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      */


var _utils = require("../utils");

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var StaticBackend = function () {
    function StaticBackend(store) {
        _classCallCheck(this, StaticBackend);

        this.store = store;
        this.onOpen();
    }

    _createClass(StaticBackend, [{
        key: "onOpen",
        value: function onOpen() {
            this.fetchData("flows");
            this.fetchData("settings");
            // this.fetchData("events") # TODO: Add events log to static viewer.
        }
    }, {
        key: "fetchData",
        value: function fetchData(resource) {
            var _this = this;

            (0, _utils.fetchApi)("./" + resource).then(function (res) {
                return res.json();
            }).then(function (json) {
                _this.receive(resource, json);
            });
        }
    }, {
        key: "receive",
        value: function receive(resource, data) {
            var type = (resource + "_RECEIVE").toUpperCase();
            this.store.dispatch({ type: type, cmd: "receive", resource: resource, data: data });
        }
    }]);

    return StaticBackend;
}();

exports.default = StaticBackend;

},{"../utils":71}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      *  The WebSocket backend is responsible for updating our knowledge of flows and events
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      *  from the REST API and live updates delivered via a WebSocket connection.
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      *  An alternative backend may use the REST API only to host static instances.
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      */


var _utils = require("../utils");

var _connection = require("../ducks/connection");

var connectionActions = _interopRequireWildcard(_connection);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var CMD_RESET = 'reset';

var WebsocketBackend = function () {
    function WebsocketBackend(store) {
        _classCallCheck(this, WebsocketBackend);

        this.activeFetches = {};
        this.store = store;
        this.connect();
    }

    _createClass(WebsocketBackend, [{
        key: "connect",
        value: function connect() {
            var _this = this;

            this.socket = new WebSocket(location.origin.replace('http', 'ws') + '/updates');
            this.socket.addEventListener('open', function () {
                return _this.onOpen();
            });
            this.socket.addEventListener('close', function (event) {
                return _this.onClose(event);
            });
            this.socket.addEventListener('message', function (msg) {
                return _this.onMessage(JSON.parse(msg.data));
            });
            this.socket.addEventListener('error', function (error) {
                return _this.onError(error);
            });
        }
    }, {
        key: "onOpen",
        value: function onOpen() {
            this.fetchData("settings");
            this.fetchData("flows");
            this.fetchData("events");
            this.fetchData("options");
            this.store.dispatch(connectionActions.startFetching());
        }
    }, {
        key: "fetchData",
        value: function fetchData(resource) {
            var _this2 = this;

            var queue = [];
            this.activeFetches[resource] = queue;
            (0, _utils.fetchApi)("./" + resource).then(function (res) {
                return res.json();
            }).then(function (json) {
                // Make sure that we are not superseded yet by the server sending a RESET.
                if (_this2.activeFetches[resource] === queue) _this2.receive(resource, json);
            });
        }
    }, {
        key: "onMessage",
        value: function onMessage(msg) {

            if (msg.cmd === CMD_RESET) {
                return this.fetchData(msg.resource);
            }
            if (msg.resource in this.activeFetches) {
                this.activeFetches[msg.resource].push(msg);
            } else {
                var type = (msg.resource + "_" + msg.cmd).toUpperCase();
                this.store.dispatch(_extends({ type: type }, msg));
            }
        }
    }, {
        key: "receive",
        value: function receive(resource, data) {
            var _this3 = this;

            var type = (resource + "_RECEIVE").toUpperCase();
            this.store.dispatch({ type: type, cmd: "receive", resource: resource, data: data });
            var queue = this.activeFetches[resource];
            delete this.activeFetches[resource];
            queue.forEach(function (msg) {
                return _this3.onMessage(msg);
            });

            if (Object.keys(this.activeFetches).length === 0) {
                // We have fetched the last resource
                this.store.dispatch(connectionActions.connectionEstablished());
            }
        }
    }, {
        key: "onClose",
        value: function onClose(closeEvent) {
            this.store.dispatch(connectionActions.connectionError("Connection closed at " + new Date().toUTCString() + " with error code " + closeEvent.code + "."));
            console.error("websocket connection closed", closeEvent);
        }
    }, {
        key: "onError",
        value: function onError() {
            // FIXME
            console.error("websocket connection errored", arguments);
        }
    }]);

    return WebsocketBackend;
}();

exports.default = WebsocketBackend;

},{"../ducks/connection":55,"../utils":71}],5:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _ContentViews = require('./ContentView/ContentViews');

var _MetaViews = require('./ContentView/MetaViews');

var MetaViews = _interopRequireWildcard(_MetaViews);

var _ShowFullContentButton = require('./ContentView/ShowFullContentButton');

var _ShowFullContentButton2 = _interopRequireDefault(_ShowFullContentButton);

var _flow = require('../ducks/ui/flow');

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ContentView.propTypes = {
    // It may seem a bit weird at the first glance:
    // Every view takes the flow and the message as props, e.g.
    // <Auto flow={flow} message={flow.request}/>
    flow: _propTypes2.default.object.isRequired,
    message: _propTypes2.default.object.isRequired
};

ContentView.isContentTooLarge = function (msg) {
    return msg.contentLength > 1024 * 1024 * (_ContentViews.ViewImage.matches(msg) ? 10 : 0.2);
};

function ContentView(props) {
    var flow = props.flow,
        message = props.message,
        contentView = props.contentView,
        isDisplayLarge = props.isDisplayLarge,
        displayLarge = props.displayLarge,
        onContentChange = props.onContentChange,
        readonly = props.readonly;


    if (message.contentLength === 0 && readonly) {
        return _react2.default.createElement(MetaViews.ContentEmpty, props);
    }

    if (message.contentLength === null && readonly) {
        return _react2.default.createElement(MetaViews.ContentMissing, props);
    }

    if (!isDisplayLarge && ContentView.isContentTooLarge(message)) {
        return _react2.default.createElement(MetaViews.ContentTooLarge, _extends({}, props, { onClick: displayLarge }));
    }

    var view = void 0;
    if (contentView === "Edit") {
        view = _react2.default.createElement(_ContentViews.Edit, { flow: flow, message: message, onChange: onContentChange });
    } else {
        view = _react2.default.createElement(_ContentViews.ViewServer, { flow: flow, message: message, contentView: contentView });
    }
    return _react2.default.createElement(
        'div',
        { className: 'contentview' },
        view,
        _react2.default.createElement(_ShowFullContentButton2.default, null)
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        contentView: state.ui.flow.contentView,
        isDisplayLarge: state.ui.flow.displayLarge
    };
}, {
    displayLarge: _flow.displayLarge,
    updateEdit: _flow.updateEdit
})(ContentView);

},{"../ducks/ui/flow":61,"./ContentView/ContentViews":9,"./ContentView/MetaViews":11,"./ContentView/ShowFullContentButton":12,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],6:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = CodeEditor;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactCodemirror = require('react-codemirror');

var _reactCodemirror2 = _interopRequireDefault(_reactCodemirror);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

CodeEditor.propTypes = {
    content: _propTypes2.default.string.isRequired,
    onChange: _propTypes2.default.func.isRequired
};

function CodeEditor(_ref) {
    var content = _ref.content,
        onChange = _ref.onChange;


    var options = {
        lineNumbers: true
    };
    return _react2.default.createElement(
        'div',
        { className: 'codeeditor', onKeyDown: function onKeyDown(e) {
                return e.stopPropagation();
            } },
        _react2.default.createElement(_reactCodemirror2.default, { value: content, onChange: onChange, options: options })
    );
}

},{"prop-types":"prop-types","react":"react","react-codemirror":"react-codemirror"}],7:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

exports.default = withContentLoader;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _utils = require('../../flow/utils.js');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function withContentLoader(View) {
    var _class, _temp;

    return _temp = _class = function (_React$Component) {
        _inherits(_class, _React$Component);

        function _class(props) {
            _classCallCheck(this, _class);

            var _this = _possibleConstructorReturn(this, (_class.__proto__ || Object.getPrototypeOf(_class)).call(this, props));

            _this.state = {
                content: undefined,
                request: undefined
            };
            return _this;
        }

        _createClass(_class, [{
            key: 'componentWillMount',
            value: function componentWillMount() {
                this.updateContent(this.props);
            }
        }, {
            key: 'componentWillReceiveProps',
            value: function componentWillReceiveProps(nextProps) {
                if (nextProps.message.content !== this.props.message.content || nextProps.message.contentHash !== this.props.message.contentHash || nextProps.contentView !== this.props.contentView) {
                    this.updateContent(nextProps);
                }
            }
        }, {
            key: 'componentWillUnmount',
            value: function componentWillUnmount() {
                if (this.state.request) {
                    this.state.request.abort();
                }
            }
        }, {
            key: 'updateContent',
            value: function updateContent(props) {
                if (this.state.request) {
                    this.state.request.abort();
                }
                // We have a few special cases where we do not need to make an HTTP request.
                if (props.message.content !== undefined) {
                    return this.setState({ request: undefined, content: props.message.content });
                }
                if (props.message.contentLength === 0 || props.message.contentLength === null) {
                    return this.setState({ request: undefined, content: "" });
                }

                var requestUrl = _utils.MessageUtils.getContentURL(props.flow, props.message, props.contentView);

                // We use XMLHttpRequest instead of fetch() because fetch() is not (yet) abortable.
                var request = new XMLHttpRequest();
                request.addEventListener("load", this.requestComplete.bind(this, request));
                request.addEventListener("error", this.requestFailed.bind(this, request));
                request.open("GET", requestUrl);
                request.send();
                this.setState({ request: request, content: undefined });
            }
        }, {
            key: 'requestComplete',
            value: function requestComplete(request, e) {
                if (request !== this.state.request) {
                    return; // Stale request
                }
                this.setState({
                    content: request.responseText,
                    request: undefined
                });
            }
        }, {
            key: 'requestFailed',
            value: function requestFailed(request, e) {
                if (request !== this.state.request) {
                    return; // Stale request
                }
                console.error(e);
                // FIXME: Better error handling
                this.setState({
                    content: "Error getting content.",
                    request: undefined
                });
            }
        }, {
            key: 'render',
            value: function render() {
                return this.state.content !== undefined ? _react2.default.createElement(View, _extends({ content: this.state.content }, this.props)) : _react2.default.createElement(
                    'div',
                    { className: 'text-center' },
                    _react2.default.createElement('i', { className: 'fa fa-spinner fa-spin' })
                );
            }
        }]);

        return _class;
    }(_react2.default.Component), _class.displayName = View.displayName || View.name, _class.matches = View.matches, _class.propTypes = _extends({}, View.propTypes, {
        content: _propTypes2.default.string, // mark as non-required
        flow: _propTypes2.default.object.isRequired,
        message: _propTypes2.default.object.isRequired
    }), _temp;
};

},{"../../flow/utils.js":69,"prop-types":"prop-types","react":"react"}],8:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _ViewSelector = require('./ViewSelector');

var _ViewSelector2 = _interopRequireDefault(_ViewSelector);

var _UploadContentButton = require('./UploadContentButton');

var _UploadContentButton2 = _interopRequireDefault(_UploadContentButton);

var _DownloadContentButton = require('./DownloadContentButton');

var _DownloadContentButton2 = _interopRequireDefault(_DownloadContentButton);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ContentViewOptions.propTypes = {
    flow: _propTypes2.default.object.isRequired,
    message: _propTypes2.default.object.isRequired
};

function ContentViewOptions(_ref) {
    var flow = _ref.flow,
        message = _ref.message,
        uploadContent = _ref.uploadContent,
        readonly = _ref.readonly,
        contentViewDescription = _ref.contentViewDescription;

    return _react2.default.createElement(
        'div',
        { className: 'view-options' },
        readonly ? _react2.default.createElement(_ViewSelector2.default, { message: message }) : _react2.default.createElement(
            'span',
            null,
            _react2.default.createElement(
                'b',
                null,
                'View:'
            ),
            ' edit'
        ),
        '\xA0',
        _react2.default.createElement(_DownloadContentButton2.default, { flow: flow, message: message }),
        '\xA0',
        !readonly && _react2.default.createElement(_UploadContentButton2.default, { uploadContent: uploadContent }),
        '\xA0',
        readonly && _react2.default.createElement(
            'span',
            null,
            contentViewDescription
        )
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        contentViewDescription: state.ui.flow.viewDescription,
        readonly: !state.ui.flow.modifiedFlow
    };
})(ContentViewOptions);

},{"./DownloadContentButton":10,"./UploadContentButton":13,"./ViewSelector":14,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],9:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.ViewImage = exports.ViewServer = exports.Edit = exports.PureViewServer = undefined;

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _flow = require('../../ducks/ui/flow');

var _ContentLoader = require('./ContentLoader');

var _ContentLoader2 = _interopRequireDefault(_ContentLoader);

var _utils = require('../../flow/utils');

var _CodeEditor = require('./CodeEditor');

var _CodeEditor2 = _interopRequireDefault(_CodeEditor);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var isImage = /^image\/(png|jpe?g|gif|webp|vnc.microsoft.icon|x-icon)$/i;
ViewImage.matches = function (msg) {
    return isImage.test(_utils.MessageUtils.getContentType(msg));
};
ViewImage.propTypes = {
    flow: _propTypes2.default.object.isRequired,
    message: _propTypes2.default.object.isRequired
};
function ViewImage(_ref) {
    var flow = _ref.flow,
        message = _ref.message;

    return _react2.default.createElement(
        'div',
        { className: 'flowview-image' },
        _react2.default.createElement('img', { src: _utils.MessageUtils.getContentURL(flow, message), alt: 'preview', className: 'img-thumbnail' })
    );
}

Edit.propTypes = {
    content: _propTypes2.default.string.isRequired
};

function Edit(_ref2) {
    var content = _ref2.content,
        onChange = _ref2.onChange;

    return _react2.default.createElement(_CodeEditor2.default, { content: content, onChange: onChange });
}
exports.Edit = Edit = (0, _ContentLoader2.default)(Edit);

var PureViewServer = exports.PureViewServer = function (_Component) {
    _inherits(PureViewServer, _Component);

    function PureViewServer() {
        _classCallCheck(this, PureViewServer);

        return _possibleConstructorReturn(this, (PureViewServer.__proto__ || Object.getPrototypeOf(PureViewServer)).apply(this, arguments));
    }

    _createClass(PureViewServer, [{
        key: 'componentWillMount',
        value: function componentWillMount() {
            this.setContentView(this.props);
        }
    }, {
        key: 'componentWillReceiveProps',
        value: function componentWillReceiveProps(nextProps) {
            if (nextProps.content != this.props.content) {
                this.setContentView(nextProps);
            }
        }
    }, {
        key: 'setContentView',
        value: function setContentView(props) {
            try {
                this.data = JSON.parse(props.content);
            } catch (err) {
                this.data = { lines: [], description: err.message };
            }

            props.setContentViewDescription(props.contentView != this.data.description ? this.data.description : '');
            props.setContent(this.data.lines);
        }
    }, {
        key: 'render',
        value: function render() {
            var _props = this.props,
                content = _props.content,
                contentView = _props.contentView,
                message = _props.message,
                maxLines = _props.maxLines;

            var lines = this.props.showFullContent ? this.data.lines : this.data.lines.slice(0, maxLines);
            return _react2.default.createElement(
                'div',
                null,
                ViewImage.matches(message) && _react2.default.createElement(ViewImage, this.props),
                _react2.default.createElement(
                    'pre',
                    null,
                    lines.map(function (line, i) {
                        return _react2.default.createElement(
                            'div',
                            { key: 'line' + i },
                            line.map(function (element, j) {
                                var _element = _slicedToArray(element, 2),
                                    style = _element[0],
                                    text = _element[1];

                                return _react2.default.createElement(
                                    'span',
                                    { key: 'tuple' + j, className: style },
                                    text
                                );
                            })
                        );
                    })
                )
            );
        }
    }]);

    return PureViewServer;
}(_react.Component);

PureViewServer.propTypes = {
    showFullContent: _propTypes2.default.bool.isRequired,
    maxLines: _propTypes2.default.number.isRequired,
    setContentViewDescription: _propTypes2.default.func.isRequired,
    setContent: _propTypes2.default.func.isRequired
};


var ViewServer = (0, _reactRedux.connect)(function (state) {
    return {
        showFullContent: state.ui.flow.showFullContent,
        maxLines: state.ui.flow.maxContentLines
    };
}, {
    setContentViewDescription: _flow.setContentViewDescription,
    setContent: _flow.setContent
})((0, _ContentLoader2.default)(PureViewServer));

exports.Edit = Edit;
exports.ViewServer = ViewServer;
exports.ViewImage = ViewImage;

},{"../../ducks/ui/flow":61,"../../flow/utils":69,"./CodeEditor":6,"./ContentLoader":7,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],10:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = DownloadContentButton;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _utils = require('../../flow/utils');

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

DownloadContentButton.propTypes = {
    flow: _propTypes2.default.object.isRequired,
    message: _propTypes2.default.object.isRequired
};

function DownloadContentButton(_ref) {
    var flow = _ref.flow,
        message = _ref.message;


    return _react2.default.createElement(
        'a',
        { className: 'btn btn-default btn-xs',
            href: _utils.MessageUtils.getContentURL(flow, message),
            title: 'Download the content of the flow.' },
        _react2.default.createElement('i', { className: 'fa fa-download' })
    );
}

},{"../../flow/utils":69,"prop-types":"prop-types","react":"react"}],11:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.ContentEmpty = ContentEmpty;
exports.ContentMissing = ContentMissing;
exports.ContentTooLarge = ContentTooLarge;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _utils = require('../../utils.js');

var _UploadContentButton = require('./UploadContentButton');

var _UploadContentButton2 = _interopRequireDefault(_UploadContentButton);

var _DownloadContentButton = require('./DownloadContentButton');

var _DownloadContentButton2 = _interopRequireDefault(_DownloadContentButton);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ContentEmpty(_ref) {
    var flow = _ref.flow,
        message = _ref.message;

    return _react2.default.createElement(
        'div',
        { className: 'alert alert-info' },
        'No ',
        flow.request === message ? 'request' : 'response',
        ' content.'
    );
}

function ContentMissing(_ref2) {
    var flow = _ref2.flow,
        message = _ref2.message;

    return _react2.default.createElement(
        'div',
        { className: 'alert alert-info' },
        flow.request === message ? 'Request' : 'Response',
        ' content missing.'
    );
}

function ContentTooLarge(_ref3) {
    var message = _ref3.message,
        onClick = _ref3.onClick,
        uploadContent = _ref3.uploadContent,
        flow = _ref3.flow;

    return _react2.default.createElement(
        'div',
        null,
        _react2.default.createElement(
            'div',
            { className: 'alert alert-warning' },
            _react2.default.createElement(
                'button',
                { onClick: onClick, className: 'btn btn-xs btn-warning pull-right' },
                'Display anyway'
            ),
            (0, _utils.formatSize)(message.contentLength),
            ' content size.'
        ),
        _react2.default.createElement(
            'div',
            { className: 'view-options text-center' },
            _react2.default.createElement(_UploadContentButton2.default, { uploadContent: uploadContent }),
            '\xA0',
            _react2.default.createElement(_DownloadContentButton2.default, { flow: flow, message: message })
        )
    );
}

},{"../../utils.js":71,"./DownloadContentButton":10,"./UploadContentButton":13,"react":"react"}],12:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.ShowFullContentButton = ShowFullContentButton;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _reactDom = require('react-dom');

var _Button = require('../common/Button');

var _Button2 = _interopRequireDefault(_Button);

var _flow = require('../../ducks/ui/flow');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ShowFullContentButton.propTypes = {
    setShowFullContent: _propTypes2.default.func.isRequired,
    showFullContent: _propTypes2.default.bool.isRequired
};

function ShowFullContentButton(_ref) {
    var setShowFullContent = _ref.setShowFullContent,
        showFullContent = _ref.showFullContent,
        visibleLines = _ref.visibleLines,
        contentLines = _ref.contentLines;


    return !showFullContent && _react2.default.createElement(
        'div',
        null,
        _react2.default.createElement(
            _Button2.default,
            { className: 'view-all-content-btn btn-xs', onClick: function onClick() {
                    return setShowFullContent();
                } },
            'Show full content'
        ),
        _react2.default.createElement(
            'span',
            { className: 'pull-right' },
            ' ',
            visibleLines,
            '/',
            contentLines,
            ' are visible \xA0 '
        )
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        showFullContent: state.ui.flow.showFullContent,
        visibleLines: state.ui.flow.maxContentLines,
        contentLines: state.ui.flow.content.length

    };
}, {
    setShowFullContent: _flow.setShowFullContent
})(ShowFullContentButton);

},{"../../ducks/ui/flow":61,"../common/Button":46,"prop-types":"prop-types","react":"react","react-dom":"react-dom","react-redux":"react-redux"}],13:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = UploadContentButton;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _FileChooser = require('../common/FileChooser');

var _FileChooser2 = _interopRequireDefault(_FileChooser);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

UploadContentButton.propTypes = {
    uploadContent: _propTypes2.default.func.isRequired
};

function UploadContentButton(_ref) {
    var uploadContent = _ref.uploadContent;


    return _react2.default.createElement(_FileChooser2.default, {
        icon: 'fa-upload',
        title: 'Upload a file to replace the content.',
        onOpenFile: uploadContent,
        className: 'btn btn-default btn-xs' });
}

},{"../common/FileChooser":49,"prop-types":"prop-types","react":"react"}],14:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.ViewSelector = ViewSelector;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _flow = require('../../ducks/ui/flow');

var _Dropdown = require('../common/Dropdown');

var _Dropdown2 = _interopRequireDefault(_Dropdown);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ViewSelector.propTypes = {
    contentViews: _propTypes2.default.array.isRequired,
    activeView: _propTypes2.default.string.isRequired,
    setContentView: _propTypes2.default.func.isRequired
};

function ViewSelector(_ref) {
    var contentViews = _ref.contentViews,
        activeView = _ref.activeView,
        setContentView = _ref.setContentView;

    var inner = _react2.default.createElement(
        'span',
        null,
        ' ',
        _react2.default.createElement(
            'b',
            null,
            'View:'
        ),
        ' ',
        activeView.toLowerCase(),
        ' ',
        _react2.default.createElement('span', { className: 'caret' }),
        ' '
    );

    return _react2.default.createElement(
        _Dropdown2.default,
        { dropup: true, className: 'pull-left', btnClass: 'btn btn-default btn-xs', text: inner },
        contentViews.map(function (name) {
            return _react2.default.createElement(
                'a',
                { href: '#', key: name, onClick: function onClick(e) {
                        e.preventDefault();setContentView(name);
                    } },
                name.toLowerCase().replace('_', ' ')
            );
        })
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        contentViews: state.settings.contentViews,
        activeView: state.ui.flow.contentView
    };
}, {
    setContentView: _flow.setContentView
})(ViewSelector);

},{"../../ducks/ui/flow":61,"../common/Dropdown":48,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],15:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.PureEventLog = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _eventLog = require('../ducks/eventLog');

var _ToggleButton = require('./common/ToggleButton');

var _ToggleButton2 = _interopRequireDefault(_ToggleButton);

var _EventList = require('./EventLog/EventList');

var _EventList2 = _interopRequireDefault(_EventList);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var PureEventLog = exports.PureEventLog = function (_Component) {
    _inherits(PureEventLog, _Component);

    function PureEventLog(props, context) {
        _classCallCheck(this, PureEventLog);

        var _this = _possibleConstructorReturn(this, (PureEventLog.__proto__ || Object.getPrototypeOf(PureEventLog)).call(this, props, context));

        _this.state = { height: _this.props.defaultHeight };

        _this.onDragStart = _this.onDragStart.bind(_this);
        _this.onDragMove = _this.onDragMove.bind(_this);
        _this.onDragStop = _this.onDragStop.bind(_this);
        return _this;
    }

    _createClass(PureEventLog, [{
        key: 'onDragStart',
        value: function onDragStart(event) {
            event.preventDefault();
            this.dragStart = this.state.height + event.pageY;
            window.addEventListener('mousemove', this.onDragMove);
            window.addEventListener('mouseup', this.onDragStop);
            window.addEventListener('dragend', this.onDragStop);
        }
    }, {
        key: 'onDragMove',
        value: function onDragMove(event) {
            event.preventDefault();
            this.setState({ height: this.dragStart - event.pageY });
        }
    }, {
        key: 'onDragStop',
        value: function onDragStop(event) {
            event.preventDefault();
            window.removeEventListener('mousemove', this.onDragMove);
        }
    }, {
        key: 'render',
        value: function render() {
            var height = this.state.height;
            var _props = this.props,
                filters = _props.filters,
                events = _props.events,
                toggleFilter = _props.toggleFilter,
                close = _props.close;


            return _react2.default.createElement(
                'div',
                { className: 'eventlog', style: { height: height } },
                _react2.default.createElement(
                    'div',
                    { onMouseDown: this.onDragStart },
                    'Eventlog',
                    _react2.default.createElement(
                        'div',
                        { className: 'pull-right' },
                        ['debug', 'info', 'web', 'warn', 'error'].map(function (type) {
                            return _react2.default.createElement(_ToggleButton2.default, { key: type, text: type, checked: filters[type], onToggle: function onToggle() {
                                    return toggleFilter(type);
                                } });
                        }),
                        _react2.default.createElement('i', { onClick: close, className: 'fa fa-close' })
                    )
                ),
                _react2.default.createElement(_EventList2.default, { events: events })
            );
        }
    }]);

    return PureEventLog;
}(_react.Component);

PureEventLog.propTypes = {
    filters: _propTypes2.default.object.isRequired,
    events: _propTypes2.default.array.isRequired,
    toggleFilter: _propTypes2.default.func.isRequired,
    close: _propTypes2.default.func.isRequired,
    defaultHeight: _propTypes2.default.number
};
PureEventLog.defaultProps = {
    defaultHeight: 200
};
exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        filters: state.eventLog.filters,
        events: state.eventLog.view
    };
}, {
    close: _eventLog.toggleVisibility,
    toggleFilter: _eventLog.toggleFilter
})(PureEventLog);

},{"../ducks/eventLog":56,"./EventLog/EventList":16,"./common/ToggleButton":52,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],16:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactDom = require('react-dom');

var _reactDom2 = _interopRequireDefault(_reactDom);

var _shallowequal = require('shallowequal');

var _shallowequal2 = _interopRequireDefault(_shallowequal);

var _AutoScroll = require('../helpers/AutoScroll');

var _AutoScroll2 = _interopRequireDefault(_AutoScroll);

var _VirtualScroll = require('../helpers/VirtualScroll');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var EventLogList = function (_Component) {
    _inherits(EventLogList, _Component);

    function EventLogList(props) {
        _classCallCheck(this, EventLogList);

        var _this = _possibleConstructorReturn(this, (EventLogList.__proto__ || Object.getPrototypeOf(EventLogList)).call(this, props));

        _this.heights = {};
        _this.state = { vScroll: (0, _VirtualScroll.calcVScroll)() };

        _this.onViewportUpdate = _this.onViewportUpdate.bind(_this);
        return _this;
    }

    _createClass(EventLogList, [{
        key: 'componentDidMount',
        value: function componentDidMount() {
            window.addEventListener('resize', this.onViewportUpdate);
            this.onViewportUpdate();
        }
    }, {
        key: 'componentWillUnmount',
        value: function componentWillUnmount() {
            window.removeEventListener('resize', this.onViewportUpdate);
        }
    }, {
        key: 'componentDidUpdate',
        value: function componentDidUpdate() {
            this.onViewportUpdate();
        }
    }, {
        key: 'onViewportUpdate',
        value: function onViewportUpdate() {
            var _this2 = this;

            var viewport = _reactDom2.default.findDOMNode(this);

            var vScroll = (0, _VirtualScroll.calcVScroll)({
                itemCount: this.props.events.length,
                rowHeight: this.props.rowHeight,
                viewportTop: viewport.scrollTop,
                viewportHeight: viewport.offsetHeight,
                itemHeights: this.props.events.map(function (entry) {
                    return _this2.heights[entry.id];
                })
            });

            if (!(0, _shallowequal2.default)(this.state.vScroll, vScroll)) {
                this.setState({ vScroll: vScroll });
            }
        }
    }, {
        key: 'setHeight',
        value: function setHeight(id, node) {
            if (node && !this.heights[id]) {
                var height = node.offsetHeight;
                if (this.heights[id] !== height) {
                    this.heights[id] = height;
                    this.onViewportUpdate();
                }
            }
        }
    }, {
        key: 'render',
        value: function render() {
            var _this3 = this;

            var vScroll = this.state.vScroll;
            var events = this.props.events;


            return _react2.default.createElement(
                'pre',
                { onScroll: this.onViewportUpdate },
                _react2.default.createElement('div', { style: { height: vScroll.paddingTop } }),
                events.slice(vScroll.start, vScroll.end).map(function (event) {
                    return _react2.default.createElement(
                        'div',
                        { key: event.id, ref: function ref(node) {
                                return _this3.setHeight(event.id, node);
                            } },
                        _react2.default.createElement(LogIcon, { event: event }),
                        event.message
                    );
                }),
                _react2.default.createElement('div', { style: { height: vScroll.paddingBottom } })
            );
        }
    }]);

    return EventLogList;
}(_react.Component);

EventLogList.propTypes = {
    events: _propTypes2.default.array.isRequired,
    rowHeight: _propTypes2.default.number
};
EventLogList.defaultProps = {
    rowHeight: 18
};


function LogIcon(_ref) {
    var event = _ref.event;

    var icon = {
        web: 'html5',
        debug: 'bug',
        warn: 'exclamation-triangle',
        error: 'ban'
    }[event.level] || 'info';
    return _react2.default.createElement('i', { className: 'fa fa-fw fa-' + icon });
}

exports.default = (0, _AutoScroll2.default)(EventLogList);

},{"../helpers/AutoScroll":53,"../helpers/VirtualScroll":54,"prop-types":"prop-types","react":"react","react-dom":"react-dom","shallowequal":"shallowequal"}],17:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.PureFlowTable = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactDom = require('react-dom');

var _reactDom2 = _interopRequireDefault(_reactDom);

var _reactRedux = require('react-redux');

var _shallowequal = require('shallowequal');

var _shallowequal2 = _interopRequireDefault(_shallowequal);

var _AutoScroll = require('./helpers/AutoScroll');

var _AutoScroll2 = _interopRequireDefault(_AutoScroll);

var _VirtualScroll = require('./helpers/VirtualScroll');

var _FlowTableHead = require('./FlowTable/FlowTableHead');

var _FlowTableHead2 = _interopRequireDefault(_FlowTableHead);

var _FlowRow = require('./FlowTable/FlowRow');

var _FlowRow2 = _interopRequireDefault(_FlowRow);

var _filt = require('../filt/filt');

var _filt2 = _interopRequireDefault(_filt);

var _flows = require('../ducks/flows');

var flowsActions = _interopRequireWildcard(_flows);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var FlowTable = function (_React$Component) {
    _inherits(FlowTable, _React$Component);

    function FlowTable(props, context) {
        _classCallCheck(this, FlowTable);

        var _this = _possibleConstructorReturn(this, (FlowTable.__proto__ || Object.getPrototypeOf(FlowTable)).call(this, props, context));

        _this.state = { vScroll: (0, _VirtualScroll.calcVScroll)() };
        _this.onViewportUpdate = _this.onViewportUpdate.bind(_this);
        return _this;
    }

    _createClass(FlowTable, [{
        key: 'componentWillMount',
        value: function componentWillMount() {
            window.addEventListener('resize', this.onViewportUpdate);
        }
    }, {
        key: 'componentWillUnmount',
        value: function componentWillUnmount() {
            window.removeEventListener('resize', this.onViewportUpdate);
        }
    }, {
        key: 'componentDidUpdate',
        value: function componentDidUpdate() {
            this.onViewportUpdate();

            if (!this.shouldScrollIntoView) {
                return;
            }

            this.shouldScrollIntoView = false;

            var _props = this.props,
                rowHeight = _props.rowHeight,
                flows = _props.flows,
                selected = _props.selected;

            var viewport = _reactDom2.default.findDOMNode(this);
            var head = _reactDom2.default.findDOMNode(this.refs.head);

            var headHeight = head ? head.offsetHeight : 0;

            var rowTop = flows.indexOf(selected) * rowHeight + headHeight;
            var rowBottom = rowTop + rowHeight;

            var viewportTop = viewport.scrollTop;
            var viewportHeight = viewport.offsetHeight;

            // Account for pinned thead
            if (rowTop - headHeight < viewportTop) {
                viewport.scrollTop = rowTop - headHeight;
            } else if (rowBottom > viewportTop + viewportHeight) {
                viewport.scrollTop = rowBottom - viewportHeight;
            }
        }
    }, {
        key: 'componentWillReceiveProps',
        value: function componentWillReceiveProps(nextProps) {
            if (nextProps.selected && nextProps.selected !== this.props.selected) {
                this.shouldScrollIntoView = true;
            }
        }
    }, {
        key: 'onViewportUpdate',
        value: function onViewportUpdate() {
            var viewport = _reactDom2.default.findDOMNode(this);
            var viewportTop = viewport.scrollTop;

            var vScroll = (0, _VirtualScroll.calcVScroll)({
                viewportTop: viewportTop,
                viewportHeight: viewport.offsetHeight,
                itemCount: this.props.flows.length,
                rowHeight: this.props.rowHeight
            });

            if (this.state.viewportTop !== viewportTop || !(0, _shallowequal2.default)(this.state.vScroll, vScroll)) {
                this.setState({ vScroll: vScroll, viewportTop: viewportTop });
            }
        }
    }, {
        key: 'render',
        value: function render() {
            var _this2 = this;

            var _state = this.state,
                vScroll = _state.vScroll,
                viewportTop = _state.viewportTop;
            var _props2 = this.props,
                flows = _props2.flows,
                selected = _props2.selected,
                highlight = _props2.highlight;

            var isHighlighted = highlight ? _filt2.default.parse(highlight) : function () {
                return false;
            };

            return _react2.default.createElement(
                'div',
                { className: 'flow-table', onScroll: this.onViewportUpdate },
                _react2.default.createElement(
                    'table',
                    null,
                    _react2.default.createElement(
                        'thead',
                        { ref: 'head', style: { transform: 'translateY(' + viewportTop + 'px)' } },
                        _react2.default.createElement(_FlowTableHead2.default, null)
                    ),
                    _react2.default.createElement(
                        'tbody',
                        null,
                        _react2.default.createElement('tr', { style: { height: vScroll.paddingTop } }),
                        flows.slice(vScroll.start, vScroll.end).map(function (flow) {
                            return _react2.default.createElement(_FlowRow2.default, {
                                key: flow.id,
                                flow: flow,
                                selected: flow === selected,
                                highlighted: isHighlighted(flow),
                                onSelect: _this2.props.selectFlow
                            });
                        }),
                        _react2.default.createElement('tr', { style: { height: vScroll.paddingBottom } })
                    )
                )
            );
        }
    }]);

    return FlowTable;
}(_react2.default.Component);

FlowTable.propTypes = {
    selectFlow: _propTypes2.default.func.isRequired,
    flows: _propTypes2.default.array.isRequired,
    rowHeight: _propTypes2.default.number,
    highlight: _propTypes2.default.string,
    selected: _propTypes2.default.object
};
FlowTable.defaultProps = {
    rowHeight: 32
};
var PureFlowTable = exports.PureFlowTable = (0, _AutoScroll2.default)(FlowTable);

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        flows: state.flows.view,
        highlight: state.flows.highlight,
        selected: state.flows.byId[state.flows.selected[0]]
    };
}, {
    selectFlow: flowsActions.select
})(PureFlowTable);

},{"../ducks/flows":57,"../filt/filt":68,"./FlowTable/FlowRow":19,"./FlowTable/FlowTableHead":20,"./helpers/AutoScroll":53,"./helpers/VirtualScroll":54,"prop-types":"prop-types","react":"react","react-dom":"react-dom","react-redux":"react-redux","shallowequal":"shallowequal"}],18:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.defaultColumnNames = undefined;
exports.TLSColumn = TLSColumn;
exports.IconColumn = IconColumn;
exports.PathColumn = PathColumn;
exports.MethodColumn = MethodColumn;
exports.StatusColumn = StatusColumn;
exports.SizeColumn = SizeColumn;
exports.TimeColumn = TimeColumn;
exports.TimeStampColumn = TimeStampColumn;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _utils = require('../../flow/utils.js');

var _utils2 = require('../../utils.js');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var defaultColumnNames = exports.defaultColumnNames = ["tls", "icon", "path", "method", "status", "size", "time"];

function TLSColumn(_ref) {
    var flow = _ref.flow;

    return _react2.default.createElement('td', { className: (0, _classnames2.default)('col-tls', flow.request.scheme === 'https' ? 'col-tls-https' : 'col-tls-http') });
}

TLSColumn.headerClass = 'col-tls';
TLSColumn.headerName = '';

function IconColumn(_ref2) {
    var flow = _ref2.flow;

    return _react2.default.createElement(
        'td',
        { className: 'col-icon' },
        _react2.default.createElement('div', { className: (0, _classnames2.default)('resource-icon', IconColumn.getIcon(flow)) })
    );
}

IconColumn.headerClass = 'col-icon';
IconColumn.headerName = '';

IconColumn.getIcon = function (flow) {
    if (!flow.response) {
        return 'resource-icon-plain';
    }

    var contentType = _utils.ResponseUtils.getContentType(flow.response) || '';

    // @todo We should assign a type to the flow somewhere else.
    if (flow.response.status_code === 304) {
        return 'resource-icon-not-modified';
    }
    if (300 <= flow.response.status_code && flow.response.status_code < 400) {
        return 'resource-icon-redirect';
    }
    if (contentType.indexOf('image') >= 0) {
        return 'resource-icon-image';
    }
    if (contentType.indexOf('javascript') >= 0) {
        return 'resource-icon-js';
    }
    if (contentType.indexOf('css') >= 0) {
        return 'resource-icon-css';
    }
    if (contentType.indexOf('html') >= 0) {
        return 'resource-icon-document';
    }

    return 'resource-icon-plain';
};

function PathColumn(_ref3) {
    var flow = _ref3.flow;


    var err = void 0;
    if (flow.error) {
        if (flow.error.msg === "Connection killed.") {
            err = _react2.default.createElement('i', { className: 'fa fa-fw fa-times pull-right' });
        } else {
            err = _react2.default.createElement('i', { className: 'fa fa-fw fa-exclamation pull-right' });
        }
    }
    return _react2.default.createElement(
        'td',
        { className: 'col-path' },
        flow.request.is_replay && _react2.default.createElement('i', { className: 'fa fa-fw fa-repeat pull-right' }),
        flow.intercepted && _react2.default.createElement('i', { className: 'fa fa-fw fa-pause pull-right' }),
        err,
        _utils.RequestUtils.pretty_url(flow.request)
    );
}

PathColumn.headerClass = 'col-path';
PathColumn.headerName = 'Path';

function MethodColumn(_ref4) {
    var flow = _ref4.flow;

    return _react2.default.createElement(
        'td',
        { className: 'col-method' },
        flow.request.method
    );
}

MethodColumn.headerClass = 'col-method';
MethodColumn.headerName = 'Method';

function StatusColumn(_ref5) {
    var flow = _ref5.flow;

    var color = 'darkred';

    if (flow.response && 100 <= flow.response.status_code && flow.response.status_code < 200) {
        color = 'green';
    } else if (flow.response && 200 <= flow.response.status_code && flow.response.status_code < 300) {
        color = 'darkgreen';
    } else if (flow.response && 300 <= flow.response.status_code && flow.response.status_code < 400) {
        color = 'lightblue';
    } else if (flow.response && 400 <= flow.response.status_code && flow.response.status_code < 500) {
        color = 'lightred';
    } else if (flow.response && 500 <= flow.response.status_code && flow.response.status_code < 600) {
        color = 'lightred';
    }

    return _react2.default.createElement(
        'td',
        { className: 'col-status', style: { color: color } },
        flow.response && flow.response.status_code
    );
}

StatusColumn.headerClass = 'col-status';
StatusColumn.headerName = 'Status';

function SizeColumn(_ref6) {
    var flow = _ref6.flow;

    return _react2.default.createElement(
        'td',
        { className: 'col-size' },
        (0, _utils2.formatSize)(SizeColumn.getTotalSize(flow))
    );
}

SizeColumn.getTotalSize = function (flow) {
    var total = flow.request.contentLength;
    if (flow.response) {
        total += flow.response.contentLength || 0;
    }
    return total;
};

SizeColumn.headerClass = 'col-size';
SizeColumn.headerName = 'Size';

function TimeColumn(_ref7) {
    var flow = _ref7.flow;

    return _react2.default.createElement(
        'td',
        { className: 'col-time' },
        flow.response ? (0, _utils2.formatTimeDelta)(1000 * (flow.response.timestamp_end - flow.request.timestamp_start)) : '...'
    );
}

TimeColumn.headerClass = 'col-time';
TimeColumn.headerName = 'Time';

function TimeStampColumn(_ref8) {
    var flow = _ref8.flow;

    return _react2.default.createElement(
        'td',
        { className: 'col-start' },
        flow.request.timestamp_start ? (0, _utils2.formatTimeStamp)(flow.request.timestamp_start) : '...'
    );
}

TimeStampColumn.headerClass = 'col-timestamp';
TimeStampColumn.headerName = 'TimeStamp';

exports.default = [TLSColumn, IconColumn, PathColumn, MethodColumn, StatusColumn, TimeStampColumn, SizeColumn, TimeColumn];

},{"../../flow/utils.js":69,"../../utils.js":71,"classnames":"classnames","react":"react"}],19:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _FlowColumns = require('./FlowColumns');

var _utils = require('../../utils');

var _FlowTableHead = require('./FlowTableHead');

var _reactRedux = require('react-redux');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

FlowRow.propTypes = {
    onSelect: _propTypes2.default.func.isRequired,
    flow: _propTypes2.default.object.isRequired,
    highlighted: _propTypes2.default.bool,
    selected: _propTypes2.default.bool
};

function FlowRow(_ref) {
    var flow = _ref.flow,
        selected = _ref.selected,
        highlighted = _ref.highlighted,
        onSelect = _ref.onSelect,
        displayColumnNames = _ref.displayColumnNames;

    var className = (0, _classnames2.default)({
        'selected': selected,
        'highlighted': highlighted,
        'intercepted': flow.intercepted,
        'has-request': flow.request,
        'has-response': flow.response
    });

    var displayColumns = (0, _FlowTableHead.getDisplayColumns)(displayColumnNames);

    return _react2.default.createElement(
        'tr',
        { className: className, onClick: function onClick() {
                return onSelect(flow.id);
            } },
        displayColumns.map(function (Column) {
            return _react2.default.createElement(Column, { key: Column.name, flow: flow });
        })
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        displayColumnNames: state.options["web_columns"] ? state.options["web_columns"].value : _FlowColumns.defaultColumnNames
    };
})((0, _utils.pure)(FlowRow));

},{"../../utils":71,"./FlowColumns":18,"./FlowTableHead":20,"classnames":"classnames","prop-types":"prop-types","react":"react","react-redux":"react-redux"}],20:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.getDisplayColumns = getDisplayColumns;
exports.FlowTableHead = FlowTableHead;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _FlowColumns = require('./FlowColumns');

var _FlowColumns2 = _interopRequireDefault(_FlowColumns);

var _flows = require('../../ducks/flows');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

FlowTableHead.propTypes = {
    setSort: _propTypes2.default.func.isRequired,
    sortDesc: _propTypes2.default.bool.isRequired,
    sortColumn: _propTypes2.default.string,
    displayColumnNames: _propTypes2.default.array
};

function getDisplayColumns(displayColumnNames) {
    var displayColumns = [];
    if (typeof displayColumnNames == "undefined") {
        return _FlowColumns2.default;
    }
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;

    try {
        for (var _iterator = _FlowColumns2.default[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
            var column = _step.value;

            if (displayColumnNames.includes(column.name.slice(0, -6).toLowerCase())) {
                displayColumns.push(column);
            }
        }
    } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
    } finally {
        try {
            if (!_iteratorNormalCompletion && _iterator.return) {
                _iterator.return();
            }
        } finally {
            if (_didIteratorError) {
                throw _iteratorError;
            }
        }
    }

    return displayColumns;
}

function FlowTableHead(_ref) {
    var sortColumn = _ref.sortColumn,
        sortDesc = _ref.sortDesc,
        setSort = _ref.setSort,
        displayColumnNames = _ref.displayColumnNames;

    var sortType = sortDesc ? 'sort-desc' : 'sort-asc';

    var displayColumns = getDisplayColumns(displayColumnNames);

    return _react2.default.createElement(
        'tr',
        null,
        displayColumns.map(function (Column) {
            return _react2.default.createElement(
                'th',
                { className: (0, _classnames2.default)(Column.headerClass, sortColumn === Column.name && sortType),
                    key: Column.name,
                    onClick: function onClick() {
                        return setSort(Column.name, Column.name !== sortColumn ? false : !sortDesc);
                    } },
                Column.headerName
            );
        })
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        sortDesc: state.flows.sort.desc,
        sortColumn: state.flows.sort.column,
        displayColumnNames: state.options["web_columns"] ? state.options["web_columns"].value : _FlowColumns.defaultColumnNames
    };
}, {
    setSort: _flows.setSort
})(FlowTableHead);

},{"../../ducks/flows":57,"./FlowColumns":18,"classnames":"classnames","prop-types":"prop-types","react":"react","react-redux":"react-redux"}],21:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.allTabs = undefined;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _reactRedux = require('react-redux');

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _Nav = require('./FlowView/Nav');

var _Nav2 = _interopRequireDefault(_Nav);

var _Messages = require('./FlowView/Messages');

var _Details = require('./FlowView/Details');

var _Details2 = _interopRequireDefault(_Details);

var _flow = require('../ducks/ui/flow');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var allTabs = exports.allTabs = { Request: _Messages.Request, Response: _Messages.Response, Error: _Messages.ErrorView, Details: _Details2.default };

function FlowView(_ref) {
    var flow = _ref.flow,
        tabName = _ref.tabName,
        selectTab = _ref.selectTab;


    // only display available tab names
    var tabs = ['request', 'response', 'error'].filter(function (k) {
        return flow[k];
    });
    tabs.push("details");

    if (tabs.indexOf(tabName) < 0) {
        if (tabName === 'response' && flow.error) {
            tabName = 'error';
        } else if (tabName === 'error' && flow.response) {
            tabName = 'response';
        } else {
            tabName = tabs[0];
        }
    }

    var Tab = allTabs[_lodash2.default.capitalize(tabName)];

    return _react2.default.createElement(
        'div',
        { className: 'flow-detail' },
        _react2.default.createElement(_Nav2.default, {
            tabs: tabs,
            active: tabName,
            onSelectTab: selectTab
        }),
        _react2.default.createElement(Tab, { flow: flow })
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        flow: state.flows.byId[state.flows.selected[0]],
        tabName: state.ui.flow.tab
    };
}, {
    selectTab: _flow.selectTab
})(FlowView);

},{"../ducks/ui/flow":61,"./FlowView/Details":22,"./FlowView/Messages":24,"./FlowView/Nav":25,"lodash":"lodash","react":"react","react-redux":"react-redux"}],22:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.TimeStamp = TimeStamp;
exports.ConnectionInfo = ConnectionInfo;
exports.CertificateInfo = CertificateInfo;
exports.Timing = Timing;
exports.default = Details;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _utils = require('../../utils.js');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function TimeStamp(_ref) {
    var t = _ref.t,
        deltaTo = _ref.deltaTo,
        title = _ref.title;

    return t ? _react2.default.createElement(
        'tr',
        null,
        _react2.default.createElement(
            'td',
            null,
            title,
            ':'
        ),
        _react2.default.createElement(
            'td',
            null,
            (0, _utils.formatTimeStamp)(t),
            deltaTo && _react2.default.createElement(
                'span',
                { className: 'text-muted' },
                '(',
                (0, _utils.formatTimeDelta)(1000 * (t - deltaTo)),
                ')'
            )
        )
    ) : _react2.default.createElement('tr', null);
}

function ConnectionInfo(_ref2) {
    var conn = _ref2.conn;

    return _react2.default.createElement(
        'table',
        { className: 'connection-table' },
        _react2.default.createElement(
            'tbody',
            null,
            _react2.default.createElement(
                'tr',
                { key: 'address' },
                _react2.default.createElement(
                    'td',
                    null,
                    'Address:'
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.address.join(':')
                )
            ),
            conn.sni && _react2.default.createElement(
                'tr',
                { key: 'sni' },
                _react2.default.createElement(
                    'td',
                    null,
                    _react2.default.createElement(
                        'abbr',
                        { title: 'TLS Server Name Indication' },
                        'TLS SNI:'
                    )
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.sni
                )
            ),
            conn.tls_version && _react2.default.createElement(
                'tr',
                { key: 'tls_version' },
                _react2.default.createElement(
                    'td',
                    null,
                    'TLS version:'
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.tls_version
                )
            ),
            conn.cipher_name && _react2.default.createElement(
                'tr',
                { key: 'cipher_name' },
                _react2.default.createElement(
                    'td',
                    null,
                    'cipher name:'
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.cipher_name
                )
            ),
            conn.alpn_proto_negotiated && _react2.default.createElement(
                'tr',
                { key: 'ALPN' },
                _react2.default.createElement(
                    'td',
                    null,
                    _react2.default.createElement(
                        'abbr',
                        { title: 'ALPN protocol negotiated' },
                        'ALPN:'
                    )
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.alpn_proto_negotiated
                )
            ),
            conn.ip_address && _react2.default.createElement(
                'tr',
                { key: 'ip_address' },
                _react2.default.createElement(
                    'td',
                    null,
                    'Resolved address:'
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.ip_address.join(':')
                )
            ),
            conn.source_address && _react2.default.createElement(
                'tr',
                { key: 'source_address' },
                _react2.default.createElement(
                    'td',
                    null,
                    'Source address:'
                ),
                _react2.default.createElement(
                    'td',
                    null,
                    conn.source_address.join(':')
                )
            )
        )
    );
}

function CertificateInfo(_ref3) {
    var flow = _ref3.flow;

    // @todo We should fetch human-readable certificate representation from the server
    return _react2.default.createElement(
        'div',
        null,
        flow.client_conn.cert && [_react2.default.createElement(
            'h4',
            { key: 'name' },
            'Client Certificate'
        ), _react2.default.createElement(
            'pre',
            { key: 'value', style: { maxHeight: 100 } },
            flow.client_conn.cert
        )],
        flow.server_conn.cert && [_react2.default.createElement(
            'h4',
            { key: 'name' },
            'Server Certificate'
        ), _react2.default.createElement(
            'pre',
            { key: 'value', style: { maxHeight: 100 } },
            flow.server_conn.cert
        )]
    );
}

function Timing(_ref4) {
    var flow = _ref4.flow;
    var sc = flow.server_conn,
        cc = flow.client_conn,
        req = flow.request,
        res = flow.response;


    var timestamps = [{
        title: "Server conn. initiated",
        t: sc.timestamp_start,
        deltaTo: req.timestamp_start
    }, {
        title: "Server conn. TCP handshake",
        t: sc.timestamp_tcp_setup,
        deltaTo: req.timestamp_start
    }, {
        title: "Server conn. SSL handshake",
        t: sc.timestamp_ssl_setup,
        deltaTo: req.timestamp_start
    }, {
        title: "Client conn. established",
        t: cc.timestamp_start,
        deltaTo: req.timestamp_start
    }, {
        title: "Client conn. SSL handshake",
        t: cc.timestamp_ssl_setup,
        deltaTo: req.timestamp_start
    }, {
        title: "First request byte",
        t: req.timestamp_start
    }, {
        title: "Request complete",
        t: req.timestamp_end,
        deltaTo: req.timestamp_start
    }, res && {
        title: "First response byte",
        t: res.timestamp_start,
        deltaTo: req.timestamp_start
    }, res && {
        title: "Response complete",
        t: res.timestamp_end,
        deltaTo: req.timestamp_start
    }];

    return _react2.default.createElement(
        'div',
        null,
        _react2.default.createElement(
            'h4',
            null,
            'Timing'
        ),
        _react2.default.createElement(
            'table',
            { className: 'timing-table' },
            _react2.default.createElement(
                'tbody',
                null,
                timestamps.filter(function (v) {
                    return v;
                }).sort(function (a, b) {
                    return a.t - b.t;
                }).map(function (item) {
                    return _react2.default.createElement(TimeStamp, _extends({ key: item.title }, item));
                })
            )
        )
    );
}

function Details(_ref5) {
    var flow = _ref5.flow;

    return _react2.default.createElement(
        'section',
        { className: 'detail' },
        _react2.default.createElement(
            'h4',
            null,
            'Client Connection'
        ),
        _react2.default.createElement(ConnectionInfo, { conn: flow.client_conn }),
        flow.server_conn.address && [_react2.default.createElement(
            'h4',
            null,
            'Server Connection'
        ), _react2.default.createElement(ConnectionInfo, { conn: flow.server_conn })],
        _react2.default.createElement(CertificateInfo, { flow: flow }),
        _react2.default.createElement(Timing, { flow: flow })
    );
}

},{"../../utils.js":71,"lodash":"lodash","react":"react"}],23:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.HeaderEditor = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactDom = require('react-dom');

var _reactDom2 = _interopRequireDefault(_reactDom);

var _ValueEditor = require('../ValueEditor/ValueEditor');

var _ValueEditor2 = _interopRequireDefault(_ValueEditor);

var _utils = require('../../utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var HeaderEditor = exports.HeaderEditor = function (_Component) {
    _inherits(HeaderEditor, _Component);

    function HeaderEditor(props) {
        _classCallCheck(this, HeaderEditor);

        var _this = _possibleConstructorReturn(this, (HeaderEditor.__proto__ || Object.getPrototypeOf(HeaderEditor)).call(this, props));

        _this.onKeyDown = _this.onKeyDown.bind(_this);
        return _this;
    }

    _createClass(HeaderEditor, [{
        key: 'render',
        value: function render() {
            var _props = this.props,
                onTab = _props.onTab,
                props = _objectWithoutProperties(_props, ['onTab']);

            return _react2.default.createElement(_ValueEditor2.default, _extends({}, props, {
                onKeyDown: this.onKeyDown
            }));
        }
    }, {
        key: 'focus',
        value: function focus() {
            _reactDom2.default.findDOMNode(this).focus();
        }
    }, {
        key: 'onKeyDown',
        value: function onKeyDown(e) {
            switch (e.keyCode) {
                case _utils.Key.BACKSPACE:
                    var s = window.getSelection().getRangeAt(0);
                    if (s.startOffset === 0 && s.endOffset === 0) {
                        this.props.onRemove(e);
                    }
                    break;
                case _utils.Key.ENTER:
                case _utils.Key.TAB:
                    if (!e.shiftKey) {
                        this.props.onTab(e);
                    }
                    break;
            }
        }
    }]);

    return HeaderEditor;
}(_react.Component);

var Headers = function (_Component2) {
    _inherits(Headers, _Component2);

    function Headers() {
        _classCallCheck(this, Headers);

        return _possibleConstructorReturn(this, (Headers.__proto__ || Object.getPrototypeOf(Headers)).apply(this, arguments));
    }

    _createClass(Headers, [{
        key: 'onChange',
        value: function onChange(row, col, val) {
            var nextHeaders = _.cloneDeep(this.props.message[this.props.type]);

            nextHeaders[row][col] = val;

            if (!nextHeaders[row][0] && !nextHeaders[row][1]) {
                // do not delete last row
                if (nextHeaders.length === 1) {
                    nextHeaders[0][0] = 'Name';
                    nextHeaders[0][1] = 'Value';
                } else {
                    nextHeaders.splice(row, 1);
                    // manually move selection target if this has been the last row.
                    if (row === nextHeaders.length) {
                        this._nextSel = row - 1 + '-value';
                    }
                }
            }

            this.props.onChange(nextHeaders);
        }
    }, {
        key: 'edit',
        value: function edit() {
            this.refs['0-key'].focus();
        }
    }, {
        key: 'onTab',
        value: function onTab(row, col, e) {
            var headers = this.props.message[this.props.type];

            if (col === 0) {
                this._nextSel = row + '-value';
                return;
            }
            if (row !== headers.length - 1) {
                this._nextSel = row + 1 + '-key';
                return;
            }

            e.preventDefault();

            var nextHeaders = _.cloneDeep(this.props.message[this.props.type]);
            nextHeaders.push(['Name', 'Value']);
            this.props.onChange(nextHeaders);
            this._nextSel = row + 1 + '-key';
        }
    }, {
        key: 'componentDidUpdate',
        value: function componentDidUpdate() {
            if (this._nextSel && this.refs[this._nextSel]) {
                this.refs[this._nextSel].focus();
                this._nextSel = undefined;
            }
        }
    }, {
        key: 'onRemove',
        value: function onRemove(row, col, e) {
            if (col === 1) {
                e.preventDefault();
                this.refs[row + '-key'].focus();
            } else if (row > 0) {
                e.preventDefault();
                this.refs[row - 1 + '-value'].focus();
            }
        }
    }, {
        key: 'render',
        value: function render() {
            var _this3 = this;

            var _props2 = this.props,
                message = _props2.message,
                readonly = _props2.readonly;

            if (message[this.props.type]) {
                return _react2.default.createElement(
                    'table',
                    { className: 'header-table' },
                    _react2.default.createElement(
                        'tbody',
                        null,
                        message[this.props.type].map(function (header, i) {
                            return _react2.default.createElement(
                                'tr',
                                { key: i },
                                _react2.default.createElement(
                                    'td',
                                    { className: 'header-name' },
                                    _react2.default.createElement(HeaderEditor, {
                                        ref: i + '-key',
                                        content: header[0],
                                        readonly: readonly,
                                        onDone: function onDone(val) {
                                            return _this3.onChange(i, 0, val);
                                        },
                                        onRemove: function onRemove(event) {
                                            return _this3.onRemove(i, 0, event);
                                        },
                                        onTab: function onTab(event) {
                                            return _this3.onTab(i, 0, event);
                                        }
                                    }),
                                    _react2.default.createElement(
                                        'span',
                                        { className: 'header-colon' },
                                        ':'
                                    )
                                ),
                                _react2.default.createElement(
                                    'td',
                                    { className: 'header-value' },
                                    _react2.default.createElement(HeaderEditor, {
                                        ref: i + '-value',
                                        content: header[1],
                                        readonly: readonly,
                                        onDone: function onDone(val) {
                                            return _this3.onChange(i, 1, val);
                                        },
                                        onRemove: function onRemove(event) {
                                            return _this3.onRemove(i, 1, event);
                                        },
                                        onTab: function onTab(event) {
                                            return _this3.onTab(i, 1, event);
                                        }
                                    })
                                )
                            );
                        })
                    )
                );
            } else {
                return _react2.default.createElement(
                    'table',
                    { className: 'header-table' },
                    _react2.default.createElement('tbody', null)
                );
            }
        }
    }]);

    return Headers;
}(_react.Component);

Headers.propTypes = {
    onChange: _propTypes2.default.func.isRequired,
    message: _propTypes2.default.object.isRequired,
    type: _propTypes2.default.string.isRequired
};
Headers.defaultProps = {
    type: 'headers'
};
exports.default = Headers;

},{"../../utils":71,"../ValueEditor/ValueEditor":45,"prop-types":"prop-types","react":"react","react-dom":"react-dom"}],24:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.Response = exports.Request = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.ErrorView = ErrorView;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _utils = require('../../flow/utils.js');

var _utils2 = require('../../utils.js');

var _ContentView = require('../ContentView');

var _ContentView2 = _interopRequireDefault(_ContentView);

var _ContentViewOptions = require('../ContentView/ContentViewOptions');

var _ContentViewOptions2 = _interopRequireDefault(_ContentViewOptions);

var _ValidateEditor = require('../ValueEditor/ValidateEditor');

var _ValidateEditor2 = _interopRequireDefault(_ValidateEditor);

var _ValueEditor = require('../ValueEditor/ValueEditor');

var _ValueEditor2 = _interopRequireDefault(_ValueEditor);

var _HideInStatic = require('../common/HideInStatic');

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

var _Headers = require('./Headers');

var _Headers2 = _interopRequireDefault(_Headers);

var _flow = require('../../ducks/ui/flow');

var _flows = require('../../ducks/flows');

var FlowActions = _interopRequireWildcard(_flows);

var _ToggleEdit = require('./ToggleEdit');

var _ToggleEdit2 = _interopRequireDefault(_ToggleEdit);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function RequestLine(_ref) {
    var flow = _ref.flow,
        readonly = _ref.readonly,
        updateFlow = _ref.updateFlow;

    return _react2.default.createElement(
        'div',
        { className: 'first-line request-line' },
        _react2.default.createElement(
            'div',
            null,
            _react2.default.createElement(_ValueEditor2.default, {
                content: flow.request.method,
                readonly: readonly,
                onDone: function onDone(method) {
                    return updateFlow({ request: { method: method } });
                }
            }),
            '\xA0',
            _react2.default.createElement(_ValidateEditor2.default, {
                content: _utils.RequestUtils.pretty_url(flow.request),
                readonly: readonly,
                onDone: function onDone(url) {
                    return updateFlow({ request: _extends({ path: '' }, (0, _utils.parseUrl)(url)) });
                },
                isValid: function isValid(url) {
                    return !!(0, _utils.parseUrl)(url).host;
                }
            }),
            '\xA0',
            _react2.default.createElement(_ValidateEditor2.default, {
                content: flow.request.http_version,
                readonly: readonly,
                onDone: function onDone(http_version) {
                    return updateFlow({ request: { http_version: http_version } });
                },
                isValid: _utils.isValidHttpVersion
            })
        )
    );
}

function ResponseLine(_ref2) {
    var flow = _ref2.flow,
        readonly = _ref2.readonly,
        updateFlow = _ref2.updateFlow;

    return _react2.default.createElement(
        'div',
        { className: 'first-line response-line' },
        _react2.default.createElement(_ValidateEditor2.default, {
            content: flow.response.http_version,
            readonly: readonly,
            onDone: function onDone(nextVer) {
                return updateFlow({ response: { http_version: nextVer } });
            },
            isValid: _utils.isValidHttpVersion
        }),
        '\xA0',
        _react2.default.createElement(_ValidateEditor2.default, {
            content: flow.response.status_code + '',
            readonly: readonly,
            onDone: function onDone(code) {
                return updateFlow({ response: { code: parseInt(code) } });
            },
            isValid: function isValid(code) {
                return (/^\d+$/.test(code)
                );
            }
        }),
        '\xA0',
        _react2.default.createElement(_ValueEditor2.default, {
            content: flow.response.reason,
            readonly: readonly,
            onDone: function onDone(msg) {
                return updateFlow({ response: { msg: msg } });
            }
        })
    );
}

var Message = (0, _reactRedux.connect)(function (state) {
    return {
        flow: state.ui.flow.modifiedFlow || state.flows.byId[state.flows.selected[0]],
        isEdit: !!state.ui.flow.modifiedFlow
    };
}, {
    updateFlow: _flow.updateEdit,
    uploadContent: FlowActions.uploadContent
});

var Request = exports.Request = function (_Component) {
    _inherits(Request, _Component);

    function Request() {
        _classCallCheck(this, Request);

        return _possibleConstructorReturn(this, (Request.__proto__ || Object.getPrototypeOf(Request)).apply(this, arguments));
    }

    _createClass(Request, [{
        key: 'render',
        value: function render() {
            var _props = this.props,
                flow = _props.flow,
                isEdit = _props.isEdit,
                updateFlow = _props.updateFlow,
                _uploadContent = _props.uploadContent;

            var noContent = !isEdit && (flow.request.contentLength == 0 || flow.request.contentLength == null);
            return _react2.default.createElement(
                'section',
                { className: 'request' },
                _react2.default.createElement(
                    'article',
                    null,
                    _react2.default.createElement(_ToggleEdit2.default, null),
                    _react2.default.createElement(RequestLine, {
                        flow: flow,
                        readonly: !isEdit,
                        updateFlow: updateFlow }),
                    _react2.default.createElement(_Headers2.default, {
                        message: flow.request,
                        readonly: !isEdit,
                        onChange: function onChange(headers) {
                            return updateFlow({ request: { headers: headers } });
                        }
                    }),
                    _react2.default.createElement('hr', null),
                    _react2.default.createElement(_ContentView2.default, {
                        readonly: !isEdit,
                        flow: flow,
                        onContentChange: function onContentChange(content) {
                            return updateFlow({ request: { content: content } });
                        },
                        message: flow.request }),
                    _react2.default.createElement('hr', null),
                    _react2.default.createElement(_Headers2.default, {
                        message: flow.request,
                        readonly: !isEdit,
                        onChange: function onChange(trailers) {
                            return updateFlow({ request: { trailers: trailers } });
                        },
                        type: 'trailers'
                    })
                ),
                _react2.default.createElement(
                    _HideInStatic2.default,
                    null,
                    !noContent && _react2.default.createElement(
                        'footer',
                        null,
                        _react2.default.createElement(_ContentViewOptions2.default, {
                            flow: flow,
                            readonly: !isEdit,
                            message: flow.request,
                            uploadContent: function uploadContent(content) {
                                return _uploadContent(flow, content, "request");
                            } })
                    )
                )
            );
        }
    }]);

    return Request;
}(_react.Component);

exports.Request = Request = Message(Request);

var Response = exports.Response = function (_Component2) {
    _inherits(Response, _Component2);

    function Response() {
        _classCallCheck(this, Response);

        return _possibleConstructorReturn(this, (Response.__proto__ || Object.getPrototypeOf(Response)).apply(this, arguments));
    }

    _createClass(Response, [{
        key: 'render',
        value: function render() {
            var _props2 = this.props,
                flow = _props2.flow,
                isEdit = _props2.isEdit,
                updateFlow = _props2.updateFlow,
                _uploadContent2 = _props2.uploadContent;

            var noContent = !isEdit && (flow.response.contentLength == 0 || flow.response.contentLength == null);

            return _react2.default.createElement(
                'section',
                { className: 'response' },
                _react2.default.createElement(
                    'article',
                    null,
                    _react2.default.createElement(_ToggleEdit2.default, null),
                    _react2.default.createElement(ResponseLine, {
                        flow: flow,
                        readonly: !isEdit,
                        updateFlow: updateFlow }),
                    _react2.default.createElement(_Headers2.default, {
                        message: flow.response,
                        readonly: !isEdit,
                        onChange: function onChange(headers) {
                            return updateFlow({ response: { headers: headers } });
                        }
                    }),
                    _react2.default.createElement('hr', null),
                    _react2.default.createElement(_ContentView2.default, {
                        readonly: !isEdit,
                        flow: flow,
                        onContentChange: function onContentChange(content) {
                            return updateFlow({ response: { content: content } });
                        },
                        message: flow.response
                    }),
                    _react2.default.createElement('hr', null),
                    _react2.default.createElement(_Headers2.default, {
                        message: flow.response,
                        readonly: !isEdit,
                        onChange: function onChange(trailers) {
                            return updateFlow({ response: { trailers: trailers } });
                        },
                        type: 'trailers'
                    })
                ),
                _react2.default.createElement(
                    _HideInStatic2.default,
                    null,
                    !noContent && _react2.default.createElement(
                        'footer',
                        null,
                        _react2.default.createElement(_ContentViewOptions2.default, {
                            flow: flow,
                            message: flow.response,
                            uploadContent: function uploadContent(content) {
                                return _uploadContent2(flow, content, "response");
                            },
                            readonly: !isEdit })
                    )
                )
            );
        }
    }]);

    return Response;
}(_react.Component);

exports.Response = Response = Message(Response);

ErrorView.propTypes = {
    flow: _propTypes2.default.object.isRequired
};

function ErrorView(_ref3) {
    var flow = _ref3.flow;

    return _react2.default.createElement(
        'section',
        { className: 'error' },
        _react2.default.createElement(
            'div',
            { className: 'alert alert-warning' },
            flow.error.msg,
            _react2.default.createElement(
                'div',
                null,
                _react2.default.createElement(
                    'small',
                    null,
                    (0, _utils2.formatTimeStamp)(flow.error.timestamp)
                )
            )
        )
    );
}

},{"../../ducks/flows":57,"../../ducks/ui/flow":61,"../../flow/utils.js":69,"../../utils.js":71,"../ContentView":5,"../ContentView/ContentViewOptions":8,"../ValueEditor/ValidateEditor":44,"../ValueEditor/ValueEditor":45,"../common/HideInStatic":50,"./Headers":23,"./ToggleEdit":26,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],25:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.NavAction = undefined;
exports.default = Nav;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

NavAction.propTypes = {
    icon: _propTypes2.default.string.isRequired,
    title: _propTypes2.default.string.isRequired,
    onClick: _propTypes2.default.func.isRequired
};

function NavAction(_ref) {
    var icon = _ref.icon,
        title = _ref.title,
        _onClick = _ref.onClick;

    return _react2.default.createElement(
        'a',
        { title: title,
            href: '#',
            className: 'nav-action',
            onClick: function onClick(event) {
                event.preventDefault();
                _onClick(event);
            } },
        _react2.default.createElement('i', { className: 'fa fa-fw ' + icon })
    );
}

exports.NavAction = NavAction;
Nav.propTypes = {
    active: _propTypes2.default.string.isRequired,
    tabs: _propTypes2.default.array.isRequired,
    onSelectTab: _propTypes2.default.func.isRequired
};

function Nav(_ref2) {
    var active = _ref2.active,
        tabs = _ref2.tabs,
        onSelectTab = _ref2.onSelectTab;

    return _react2.default.createElement(
        'nav',
        { className: 'nav-tabs nav-tabs-sm' },
        tabs.map(function (tab) {
            return _react2.default.createElement(
                'a',
                { key: tab,
                    href: '#',
                    className: (0, _classnames2.default)({ active: active === tab }),
                    onClick: function onClick(event) {
                        event.preventDefault();
                        onSelectTab(tab);
                    } },
                _lodash2.default.capitalize(tab)
            );
        })
    );
}

},{"classnames":"classnames","lodash":"lodash","prop-types":"prop-types","react":"react","react-redux":"react-redux"}],26:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _flow = require('../../ducks/ui/flow');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ToggleEdit.propTypes = {
    isEdit: _propTypes2.default.bool.isRequired,
    flow: _propTypes2.default.object.isRequired,
    startEdit: _propTypes2.default.func.isRequired,
    stopEdit: _propTypes2.default.func.isRequired
};

function ToggleEdit(_ref) {
    var isEdit = _ref.isEdit,
        startEdit = _ref.startEdit,
        stopEdit = _ref.stopEdit,
        flow = _ref.flow,
        modifiedFlow = _ref.modifiedFlow;

    return _react2.default.createElement(
        'div',
        { className: 'edit-flow-container' },
        isEdit ? _react2.default.createElement(
            'a',
            { className: 'edit-flow', title: 'Finish Edit', onClick: function onClick() {
                    return stopEdit(flow, modifiedFlow);
                } },
            _react2.default.createElement('i', { className: 'fa fa-check' })
        ) : _react2.default.createElement(
            'a',
            { className: 'edit-flow', title: 'Edit Flow', onClick: function onClick() {
                    return startEdit(flow);
                } },
            _react2.default.createElement('i', { className: 'fa fa-pencil' })
        )
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        isEdit: !!state.ui.flow.modifiedFlow,
        modifiedFlow: state.ui.flow.modifiedFlow || state.flows.byId[state.flows.selected[0]],
        flow: state.flows.byId[state.flows.selected[0]]
    };
}, {
    startEdit: _flow.startEdit,
    stopEdit: _flow.stopEdit
})(ToggleEdit);

},{"../../ducks/ui/flow":61,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],27:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _utils = require('../utils.js');

var _HideInStatic = require('../components/common/HideInStatic');

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

Footer.propTypes = {
    settings: _propTypes2.default.object.isRequired
};

function Footer(_ref) {
    var settings = _ref.settings;
    var mode = settings.mode,
        intercept = settings.intercept,
        showhost = settings.showhost,
        no_upstream_cert = settings.no_upstream_cert,
        rawtcp = settings.rawtcp,
        http2 = settings.http2,
        websocket = settings.websocket,
        anticache = settings.anticache,
        anticomp = settings.anticomp,
        stickyauth = settings.stickyauth,
        stickycookie = settings.stickycookie,
        stream_large_bodies = settings.stream_large_bodies,
        listen_host = settings.listen_host,
        listen_port = settings.listen_port,
        version = settings.version,
        server = settings.server;

    return _react2.default.createElement(
        'footer',
        null,
        mode && mode != "regular" && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            mode,
            ' mode'
        ),
        intercept && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'Intercept: ',
            intercept
        ),
        showhost && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'showhost'
        ),
        no_upstream_cert && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'no-upstream-cert'
        ),
        rawtcp && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'raw-tcp'
        ),
        !http2 && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'no-http2'
        ),
        !websocket && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'no-websocket'
        ),
        anticache && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'anticache'
        ),
        anticomp && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'anticomp'
        ),
        stickyauth && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'stickyauth: ',
            stickyauth
        ),
        stickycookie && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'stickycookie: ',
            stickycookie
        ),
        stream_large_bodies && _react2.default.createElement(
            'span',
            { className: 'label label-success' },
            'stream: ',
            (0, _utils.formatSize)(stream_large_bodies)
        ),
        _react2.default.createElement(
            'div',
            { className: 'pull-right' },
            _react2.default.createElement(
                _HideInStatic2.default,
                null,
                server && _react2.default.createElement(
                    'span',
                    { className: 'label label-primary', title: 'HTTP Proxy Server Address' },
                    listen_host || "*",
                    ':',
                    listen_port
                )
            ),
            _react2.default.createElement(
                'span',
                { className: 'label label-info', title: 'Mitmproxy Version' },
                'v',
                version
            )
        )
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        settings: state.settings
    };
})(Footer);

},{"../components/common/HideInStatic":50,"../utils.js":71,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],28:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _MainMenu = require('./Header/MainMenu');

var _MainMenu2 = _interopRequireDefault(_MainMenu);

var _OptionMenu = require('./Header/OptionMenu');

var _OptionMenu2 = _interopRequireDefault(_OptionMenu);

var _FileMenu = require('./Header/FileMenu');

var _FileMenu2 = _interopRequireDefault(_FileMenu);

var _FlowMenu = require('./Header/FlowMenu');

var _FlowMenu2 = _interopRequireDefault(_FlowMenu);

var _header = require('../ducks/ui/header');

var _ConnectionIndicator = require('./Header/ConnectionIndicator');

var _ConnectionIndicator2 = _interopRequireDefault(_ConnectionIndicator);

var _HideInStatic = require('./common/HideInStatic');

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Header = function (_Component) {
    _inherits(Header, _Component);

    function Header() {
        _classCallCheck(this, Header);

        return _possibleConstructorReturn(this, (Header.__proto__ || Object.getPrototypeOf(Header)).apply(this, arguments));
    }

    _createClass(Header, [{
        key: 'handleClick',
        value: function handleClick(active, e) {
            e.preventDefault();
            this.props.setActiveMenu(active.title);
        }
    }, {
        key: 'render',
        value: function render() {
            var _this2 = this;

            var _props = this.props,
                selectedFlowId = _props.selectedFlowId,
                activeMenu = _props.activeMenu;


            var entries = [].concat(_toConsumableArray(Header.entries));
            if (selectedFlowId) entries.push(_FlowMenu2.default);

            // Make sure to have a fallback in case FlowMenu is selected but we don't have any flows
            // (e.g. because they are all deleted or not yet received)
            var Active = _.find(entries, function (e) {
                return e.title == activeMenu;
            }) || _MainMenu2.default;

            return _react2.default.createElement(
                'header',
                null,
                _react2.default.createElement(
                    'nav',
                    { className: 'nav-tabs nav-tabs-lg' },
                    _react2.default.createElement(_FileMenu2.default, null),
                    entries.map(function (Entry) {
                        return _react2.default.createElement(
                            'a',
                            { key: Entry.title,
                                href: '#',
                                className: (0, _classnames2.default)({ active: Entry === Active }),
                                onClick: function onClick(e) {
                                    return _this2.handleClick(Entry, e);
                                } },
                            Entry.title
                        );
                    }),
                    _react2.default.createElement(
                        _HideInStatic2.default,
                        null,
                        _react2.default.createElement(_ConnectionIndicator2.default, null)
                    )
                ),
                _react2.default.createElement(
                    'div',
                    null,
                    _react2.default.createElement(Active, null)
                )
            );
        }
    }]);

    return Header;
}(_react.Component);

Header.entries = [_MainMenu2.default, _OptionMenu2.default];
exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        selectedFlowId: state.flows.selected[0],
        activeMenu: state.ui.header.activeMenu
    };
}, {
    setActiveMenu: _header.setActiveMenu
})(Header);

},{"../ducks/ui/header":62,"./Header/ConnectionIndicator":29,"./Header/FileMenu":30,"./Header/FlowMenu":33,"./Header/MainMenu":34,"./Header/OptionMenu":36,"./common/HideInStatic":50,"classnames":"classnames","prop-types":"prop-types","react":"react","react-redux":"react-redux"}],29:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.ConnectionIndicator = ConnectionIndicator;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require("react-redux");

var _connection = require("../../ducks/connection");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ConnectionIndicator.propTypes = {
    state: _propTypes2.default.symbol.isRequired,
    message: _propTypes2.default.string

};
function ConnectionIndicator(_ref) {
    var state = _ref.state,
        message = _ref.message;

    switch (state) {
        case _connection.ConnectionState.INIT:
            return _react2.default.createElement(
                "span",
                { className: "connection-indicator init badge" },
                "connecting\u2026"
            );
        case _connection.ConnectionState.FETCHING:
            return _react2.default.createElement(
                "span",
                { className: "connection-indicator fetching badge" },
                "fetching data\u2026"
            );
        case _connection.ConnectionState.ESTABLISHED:
            return _react2.default.createElement(
                "span",
                { className: "connection-indicator established badge" },
                "connected"
            );
        case _connection.ConnectionState.ERROR:
            return _react2.default.createElement(
                "span",
                { className: "connection-indicator error badge",
                    title: message },
                "connection lost"
            );
        case _connection.ConnectionState.OFFLINE:
            return _react2.default.createElement(
                "span",
                { className: "connection-indicator offline badge" },
                "offline"
            );
    }
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return state.connection;
})(ConnectionIndicator);

},{"../../ducks/connection":55,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],30:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.FileMenu = FileMenu;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _FileChooser = require('../common/FileChooser');

var _FileChooser2 = _interopRequireDefault(_FileChooser);

var _Dropdown = require('../common/Dropdown');

var _Dropdown2 = _interopRequireDefault(_Dropdown);

var _flows = require('../../ducks/flows');

var flowsActions = _interopRequireWildcard(_flows);

var _modal = require('../../ducks/ui/modal');

var modalActions = _interopRequireWildcard(_modal);

var _HideInStatic = require('../common/HideInStatic');

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

FileMenu.propTypes = {
    clearFlows: _propTypes2.default.func.isRequired,
    loadFlows: _propTypes2.default.func.isRequired,
    saveFlows: _propTypes2.default.func.isRequired
};

FileMenu.onNewClick = function (e, clearFlows) {
    e.preventDefault();
    if (confirm('Delete all flows?')) clearFlows();
};

function FileMenu(_ref) {
    var clearFlows = _ref.clearFlows,
        loadFlows = _ref.loadFlows,
        saveFlows = _ref.saveFlows;

    return _react2.default.createElement(
        _Dropdown2.default,
        { className: 'pull-left', btnClass: 'special', text: 'mitmproxy' },
        _react2.default.createElement(
            'a',
            { href: '#', onClick: function onClick(e) {
                    return FileMenu.onNewClick(e, clearFlows);
                } },
            _react2.default.createElement('i', { className: 'fa fa-fw fa-trash' }),
            '\xA0Clear All'
        ),
        _react2.default.createElement(_FileChooser2.default, {
            icon: 'fa-folder-open',
            text: '\xA0Open...',
            onOpenFile: function onOpenFile(file) {
                return loadFlows(file);
            }
        }),
        _react2.default.createElement(
            'a',
            { href: '#', onClick: function onClick(e) {
                    e.preventDefault();saveFlows();
                } },
            _react2.default.createElement('i', { className: 'fa fa-fw fa-floppy-o' }),
            '\xA0Save...'
        ),
        _react2.default.createElement(
            _HideInStatic2.default,
            null,
            _react2.default.createElement(_Dropdown.Divider, null),
            _react2.default.createElement(
                'a',
                { href: 'http://mitm.it/', target: '_blank' },
                _react2.default.createElement('i', { className: 'fa fa-fw fa-external-link' }),
                '\xA0Install Certificates...'
            )
        )
    );
}

exports.default = (0, _reactRedux.connect)(null, {
    clearFlows: flowsActions.clear,
    loadFlows: flowsActions.upload,
    saveFlows: flowsActions.download
})(FileMenu);

},{"../../ducks/flows":57,"../../ducks/ui/modal":65,"../common/Dropdown":48,"../common/FileChooser":49,"../common/HideInStatic":50,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],31:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _utils = require('../../utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var FilterDocs = function (_Component) {
    _inherits(FilterDocs, _Component);

    // @todo move to redux

    function FilterDocs(props, context) {
        _classCallCheck(this, FilterDocs);

        var _this = _possibleConstructorReturn(this, (FilterDocs.__proto__ || Object.getPrototypeOf(FilterDocs)).call(this, props, context));

        _this.state = { doc: FilterDocs.doc };
        return _this;
    }

    _createClass(FilterDocs, [{
        key: 'componentWillMount',
        value: function componentWillMount() {
            var _this2 = this;

            if (!FilterDocs.xhr) {
                FilterDocs.xhr = (0, _utils.fetchApi)('/filter-help').then(function (response) {
                    return response.json();
                });
                FilterDocs.xhr.catch(function () {
                    FilterDocs.xhr = null;
                });
            }
            if (!this.state.doc) {
                FilterDocs.xhr.then(function (doc) {
                    FilterDocs.doc = doc;
                    _this2.setState({ doc: doc });
                });
            }
        }
    }, {
        key: 'render',
        value: function render() {
            var _this3 = this;

            var doc = this.state.doc;

            return !doc ? _react2.default.createElement('i', { className: 'fa fa-spinner fa-spin' }) : _react2.default.createElement(
                'table',
                { className: 'table table-condensed' },
                _react2.default.createElement(
                    'tbody',
                    null,
                    doc.commands.map(function (cmd) {
                        return _react2.default.createElement(
                            'tr',
                            { key: cmd[1], onClick: function onClick(e) {
                                    return _this3.props.selectHandler(cmd[0].split(" ")[0] + " ");
                                } },
                            _react2.default.createElement(
                                'td',
                                null,
                                cmd[0].replace(' ', '\xA0')
                            ),
                            _react2.default.createElement(
                                'td',
                                null,
                                cmd[1]
                            )
                        );
                    }),
                    _react2.default.createElement(
                        'tr',
                        { key: 'docs-link' },
                        _react2.default.createElement(
                            'td',
                            { colSpan: '2' },
                            _react2.default.createElement(
                                'a',
                                { href: 'https://mitmproxy.org/docs/latest/concepts-filters/',
                                    target: '_blank' },
                                _react2.default.createElement('i', { className: 'fa fa-external-link' }),
                                '\xA0 mitmproxy docs'
                            )
                        )
                    )
                )
            );
        }
    }]);

    return FilterDocs;
}(_react.Component);

FilterDocs.xhr = null;
FilterDocs.doc = null;
exports.default = FilterDocs;

},{"../../utils":71,"react":"react"}],32:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactDom = require('react-dom');

var _reactDom2 = _interopRequireDefault(_reactDom);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _utils = require('../../utils.js');

var _filt = require('../../filt/filt');

var _filt2 = _interopRequireDefault(_filt);

var _FilterDocs = require('./FilterDocs');

var _FilterDocs2 = _interopRequireDefault(_FilterDocs);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var FilterInput = function (_Component) {
    _inherits(FilterInput, _Component);

    function FilterInput(props, context) {
        _classCallCheck(this, FilterInput);

        // Consider both focus and mouseover for showing/hiding the tooltip,
        // because onBlur of the input is triggered before the click on the tooltip
        // finalized, hiding the tooltip just as the user clicks on it.
        var _this = _possibleConstructorReturn(this, (FilterInput.__proto__ || Object.getPrototypeOf(FilterInput)).call(this, props, context));

        _this.state = { value: _this.props.value, focus: false, mousefocus: false };

        _this.onChange = _this.onChange.bind(_this);
        _this.onFocus = _this.onFocus.bind(_this);
        _this.onBlur = _this.onBlur.bind(_this);
        _this.onKeyDown = _this.onKeyDown.bind(_this);
        _this.onMouseEnter = _this.onMouseEnter.bind(_this);
        _this.onMouseLeave = _this.onMouseLeave.bind(_this);
        _this.selectFilter = _this.selectFilter.bind(_this);
        return _this;
    }

    _createClass(FilterInput, [{
        key: 'componentWillReceiveProps',
        value: function componentWillReceiveProps(nextProps) {
            this.setState({ value: nextProps.value });
        }
    }, {
        key: 'isValid',
        value: function isValid(filt) {
            try {
                var str = filt == null ? this.state.value : filt;
                if (str) {
                    _filt2.default.parse(str);
                }
                return true;
            } catch (e) {
                return false;
            }
        }
    }, {
        key: 'getDesc',
        value: function getDesc() {
            if (!this.state.value) {
                return _react2.default.createElement(_FilterDocs2.default, { selectHandler: this.selectFilter });
            }
            try {
                return _filt2.default.parse(this.state.value).desc;
            } catch (e) {
                return '' + e;
            }
        }
    }, {
        key: 'onChange',
        value: function onChange(e) {
            var value = e.target.value;
            this.setState({ value: value });

            // Only propagate valid filters upwards.
            if (this.isValid(value)) {
                this.props.onChange(value);
            }
        }
    }, {
        key: 'onFocus',
        value: function onFocus() {
            this.setState({ focus: true });
        }
    }, {
        key: 'onBlur',
        value: function onBlur() {
            this.setState({ focus: false });
        }
    }, {
        key: 'onMouseEnter',
        value: function onMouseEnter() {
            this.setState({ mousefocus: true });
        }
    }, {
        key: 'onMouseLeave',
        value: function onMouseLeave() {
            this.setState({ mousefocus: false });
        }
    }, {
        key: 'onKeyDown',
        value: function onKeyDown(e) {
            if (e.keyCode === _utils.Key.ESC || e.keyCode === _utils.Key.ENTER) {
                this.blur();
                // If closed using ESC/ENTER, hide the tooltip.
                this.setState({ mousefocus: false });
            }
            e.stopPropagation();
        }
    }, {
        key: 'selectFilter',
        value: function selectFilter(cmd) {
            this.setState({ value: cmd });
            _reactDom2.default.findDOMNode(this.refs.input).focus();
        }
    }, {
        key: 'blur',
        value: function blur() {
            _reactDom2.default.findDOMNode(this.refs.input).blur();
        }
    }, {
        key: 'select',
        value: function select() {
            _reactDom2.default.findDOMNode(this.refs.input).select();
        }
    }, {
        key: 'render',
        value: function render() {
            var _props = this.props,
                type = _props.type,
                color = _props.color,
                placeholder = _props.placeholder;
            var _state = this.state,
                value = _state.value,
                focus = _state.focus,
                mousefocus = _state.mousefocus;

            return _react2.default.createElement(
                'div',
                { className: (0, _classnames2.default)('filter-input input-group', { 'has-error': !this.isValid() }) },
                _react2.default.createElement(
                    'span',
                    { className: 'input-group-text' },
                    _react2.default.createElement('i', { className: 'fa fa-fw fa-' + type, style: { color: color } })
                ),
                _react2.default.createElement('input', {
                    type: 'text',
                    ref: 'input',
                    placeholder: placeholder,
                    className: 'form-control',
                    value: value,
                    onChange: this.onChange,
                    onFocus: this.onFocus,
                    onBlur: this.onBlur,
                    onKeyDown: this.onKeyDown
                }),
                (focus || mousefocus) && _react2.default.createElement(
                    'div',
                    { className: 'popover bottom',
                        onMouseEnter: this.onMouseEnter,
                        onMouseLeave: this.onMouseLeave },
                    _react2.default.createElement('div', { className: 'arrow' }),
                    _react2.default.createElement(
                        'div',
                        { className: 'popover-content' },
                        this.getDesc()
                    )
                )
            );
        }
    }]);

    return FilterInput;
}(_react.Component);

exports.default = FilterInput;

},{"../../filt/filt":68,"../../utils.js":71,"./FilterDocs":31,"classnames":"classnames","prop-types":"prop-types","react":"react","react-dom":"react-dom"}],33:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.FlowMenu = FlowMenu;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require("react-redux");

var _Button = require("../common/Button");

var _Button2 = _interopRequireDefault(_Button);

var _utils = require("../../flow/utils.js");

var _flows = require("../../ducks/flows");

var flowsActions = _interopRequireWildcard(_flows);

var _HideInStatic = require("../common/HideInStatic");

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

FlowMenu.title = 'Flow';

FlowMenu.propTypes = {
    flow: _propTypes2.default.object,
    resumeFlow: _propTypes2.default.func.isRequired,
    killFlow: _propTypes2.default.func.isRequired,
    replayFlow: _propTypes2.default.func.isRequired,
    duplicateFlow: _propTypes2.default.func.isRequired,
    removeFlow: _propTypes2.default.func.isRequired,
    revertFlow: _propTypes2.default.func.isRequired
};

function FlowMenu(_ref) {
    var flow = _ref.flow,
        resumeFlow = _ref.resumeFlow,
        killFlow = _ref.killFlow,
        replayFlow = _ref.replayFlow,
        duplicateFlow = _ref.duplicateFlow,
        removeFlow = _ref.removeFlow,
        revertFlow = _ref.revertFlow;

    if (!flow) return _react2.default.createElement("div", null);
    return _react2.default.createElement(
        "div",
        null,
        _react2.default.createElement(
            _HideInStatic2.default,
            null,
            _react2.default.createElement(
                "div",
                { className: "menu-group" },
                _react2.default.createElement(
                    "div",
                    { className: "menu-content" },
                    _react2.default.createElement(
                        _Button2.default,
                        { title: "[r]eplay flow", icon: "fa-repeat text-primary",
                            onClick: function onClick() {
                                return replayFlow(flow);
                            } },
                        "Replay"
                    ),
                    _react2.default.createElement(
                        _Button2.default,
                        { title: "[D]uplicate flow", icon: "fa-copy text-info",
                            onClick: function onClick() {
                                return duplicateFlow(flow);
                            } },
                        "Duplicate"
                    ),
                    _react2.default.createElement(
                        _Button2.default,
                        { disabled: !flow || !flow.modified, title: "revert changes to flow [V]",
                            icon: "fa-history text-warning", onClick: function onClick() {
                                return revertFlow(flow);
                            } },
                        "Revert"
                    ),
                    _react2.default.createElement(
                        _Button2.default,
                        { title: "[d]elete flow", icon: "fa-trash text-danger",
                            onClick: function onClick() {
                                return removeFlow(flow);
                            } },
                        "Delete"
                    )
                ),
                _react2.default.createElement(
                    "div",
                    { className: "menu-legend" },
                    "Flow Modification"
                )
            )
        ),
        _react2.default.createElement(
            "div",
            { className: "menu-group" },
            _react2.default.createElement(
                "div",
                { className: "menu-content" },
                _react2.default.createElement(
                    _Button2.default,
                    { title: "download", icon: "fa-download",
                        onClick: function onClick() {
                            return window.location = _utils.MessageUtils.getContentURL(flow, flow.response);
                        } },
                    "Download"
                )
            ),
            _react2.default.createElement(
                "div",
                { className: "menu-legend" },
                "Export"
            )
        ),
        _react2.default.createElement(
            _HideInStatic2.default,
            null,
            _react2.default.createElement(
                "div",
                { className: "menu-group" },
                _react2.default.createElement(
                    "div",
                    { className: "menu-content" },
                    _react2.default.createElement(
                        _Button2.default,
                        { disabled: !flow || !flow.intercepted, title: "[a]ccept intercepted flow",
                            icon: "fa-play text-success", onClick: function onClick() {
                                return resumeFlow(flow);
                            } },
                        "Resume"
                    ),
                    _react2.default.createElement(
                        _Button2.default,
                        { disabled: !flow || !flow.intercepted, title: "kill intercepted flow [x]",
                            icon: "fa-times text-danger", onClick: function onClick() {
                                return killFlow(flow);
                            } },
                        "Abort"
                    )
                ),
                _react2.default.createElement(
                    "div",
                    { className: "menu-legend" },
                    "Interception"
                )
            )
        )
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        flow: state.flows.byId[state.flows.selected[0]]
    };
}, {
    resumeFlow: flowsActions.resume,
    killFlow: flowsActions.kill,
    replayFlow: flowsActions.replay,
    duplicateFlow: flowsActions.duplicate,
    removeFlow: flowsActions.remove,
    revertFlow: flowsActions.revert
})(FlowMenu);

},{"../../ducks/flows":57,"../../flow/utils.js":69,"../common/Button":46,"../common/HideInStatic":50,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],34:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = MainMenu;
exports.setIntercept = setIntercept;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require("react-redux");

var _FilterInput = require("./FilterInput");

var _FilterInput2 = _interopRequireDefault(_FilterInput);

var _settings = require("../../ducks/settings");

var _flows = require("../../ducks/flows");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

MainMenu.title = "Start";

function MainMenu() {
    return _react2.default.createElement(
        "div",
        { className: "menu-main" },
        _react2.default.createElement(FlowFilterInput, null),
        _react2.default.createElement(HighlightInput, null),
        _react2.default.createElement(InterceptInput, null)
    );
}

function setIntercept(intercept) {
    (0, _settings.update)({ intercept: intercept });
}

var InterceptInput = (0, _reactRedux.connect)(function (state) {
    return {
        value: state.settings.intercept || '',
        placeholder: 'Intercept',
        type: 'pause',
        color: 'hsl(208, 56%, 53%)'
    };
}, { onChange: setIntercept })(_FilterInput2.default);

var FlowFilterInput = (0, _reactRedux.connect)(function (state) {
    return {
        value: state.flows.filter || '',
        placeholder: 'Search',
        type: 'search',
        color: 'black'
    };
}, { onChange: _flows.setFilter })(_FilterInput2.default);

var HighlightInput = (0, _reactRedux.connect)(function (state) {
    return {
        value: state.flows.highlight || '',
        placeholder: 'Highlight',
        type: 'tag',
        color: 'hsl(48, 100%, 50%)'
    };
}, { onChange: _flows.setHighlight })(_FilterInput2.default);

},{"../../ducks/flows":57,"../../ducks/settings":60,"./FilterInput":32,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],35:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.MenuToggle = MenuToggle;
exports.SettingsToggle = SettingsToggle;
exports.EventlogToggle = EventlogToggle;

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require("react-redux");

var _settings = require("../../ducks/settings");

var _eventLog = require("../../ducks/eventLog");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

MenuToggle.propTypes = {
    value: _propTypes2.default.bool.isRequired,
    onChange: _propTypes2.default.func.isRequired,
    children: _propTypes2.default.node.isRequired
};

function MenuToggle(_ref) {
    var value = _ref.value,
        onChange = _ref.onChange,
        children = _ref.children;

    return React.createElement(
        "div",
        { className: "menu-entry" },
        React.createElement(
            "label",
            null,
            React.createElement("input", { type: "checkbox",
                checked: value,
                onChange: onChange }),
            children
        )
    );
}

SettingsToggle.propTypes = {
    setting: _propTypes2.default.string.isRequired,
    children: _propTypes2.default.node.isRequired
};

function SettingsToggle(_ref2) {
    var setting = _ref2.setting,
        children = _ref2.children,
        settings = _ref2.settings,
        updateSettings = _ref2.updateSettings;

    return React.createElement(
        MenuToggle,
        {
            value: settings[setting] || false // we don't have settings initially, so just pass false.
            , onChange: function onChange() {
                return updateSettings(_defineProperty({}, setting, !settings[setting]));
            }
        },
        children
    );
}
exports.SettingsToggle = SettingsToggle = (0, _reactRedux.connect)(function (state) {
    return {
        settings: state.settings
    };
}, {
    updateSettings: _settings.update
})(SettingsToggle);

function EventlogToggle(_ref3) {
    var toggleVisibility = _ref3.toggleVisibility,
        eventLogVisible = _ref3.eventLogVisible;

    return React.createElement(
        MenuToggle,
        {
            value: eventLogVisible,
            onChange: toggleVisibility
        },
        "Display Event Log"
    );
}
exports.EventlogToggle = EventlogToggle = (0, _reactRedux.connect)(function (state) {
    return {
        eventLogVisible: state.eventLog.visible
    };
}, {
    toggleVisibility: _eventLog.toggleVisibility
})(EventlogToggle);

},{"../../ducks/eventLog":56,"../../ducks/settings":60,"prop-types":"prop-types","react-redux":"react-redux"}],36:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _reactRedux = require("react-redux");

var _MenuToggle = require("./MenuToggle");

var _Button = require("../common/Button");

var _Button2 = _interopRequireDefault(_Button);

var _DocsLink = require("../common/DocsLink");

var _DocsLink2 = _interopRequireDefault(_DocsLink);

var _HideInStatic = require("../common/HideInStatic");

var _HideInStatic2 = _interopRequireDefault(_HideInStatic);

var _modal = require("../../ducks/ui/modal");

var modalActions = _interopRequireWildcard(_modal);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

OptionMenu.title = 'Options';

function OptionMenu(_ref) {
    var openOptions = _ref.openOptions;

    return _react2.default.createElement(
        "div",
        null,
        _react2.default.createElement(
            _HideInStatic2.default,
            null,
            _react2.default.createElement(
                "div",
                { className: "menu-group" },
                _react2.default.createElement(
                    "div",
                    { className: "menu-content" },
                    _react2.default.createElement(
                        _Button2.default,
                        { title: "Open Options", icon: "fa-cogs text-primary",
                            onClick: openOptions },
                        "Edit Options ",
                        _react2.default.createElement(
                            "sup",
                            null,
                            "alpha"
                        )
                    )
                ),
                _react2.default.createElement(
                    "div",
                    { className: "menu-legend" },
                    "Options Editor"
                )
            ),
            _react2.default.createElement(
                "div",
                { className: "menu-group" },
                _react2.default.createElement(
                    "div",
                    { className: "menu-content" },
                    _react2.default.createElement(
                        _MenuToggle.SettingsToggle,
                        { setting: "anticache" },
                        "Strip cache headers ",
                        _react2.default.createElement(_DocsLink2.default, { resource: "overview-features/#anticache" })
                    ),
                    _react2.default.createElement(
                        _MenuToggle.SettingsToggle,
                        { setting: "showhost" },
                        "Use host header for display"
                    ),
                    _react2.default.createElement(
                        _MenuToggle.SettingsToggle,
                        { setting: "ssl_insecure" },
                        "Don't verify server certificates"
                    )
                ),
                _react2.default.createElement(
                    "div",
                    { className: "menu-legend" },
                    "Quick Options"
                )
            )
        ),
        _react2.default.createElement(
            "div",
            { className: "menu-group" },
            _react2.default.createElement(
                "div",
                { className: "menu-content" },
                _react2.default.createElement(_MenuToggle.EventlogToggle, null)
            ),
            _react2.default.createElement(
                "div",
                { className: "menu-legend" },
                "View Options"
            )
        )
    );
}

exports.default = (0, _reactRedux.connect)(null, {
    openOptions: function openOptions() {
        return modalActions.setActiveModal('OptionModal');
    }
})(OptionMenu);

},{"../../ducks/ui/modal":65,"../common/Button":46,"../common/DocsLink":47,"../common/HideInStatic":50,"./MenuToggle":35,"react":"react","react-redux":"react-redux"}],37:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _Splitter = require('./common/Splitter');

var _Splitter2 = _interopRequireDefault(_Splitter);

var _FlowTable = require('./FlowTable');

var _FlowTable2 = _interopRequireDefault(_FlowTable);

var _FlowView = require('./FlowView');

var _FlowView2 = _interopRequireDefault(_FlowView);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

MainView.propTypes = {
    hasSelection: _propTypes2.default.bool.isRequired
};

function MainView(_ref) {
    var hasSelection = _ref.hasSelection;

    return _react2.default.createElement(
        'div',
        { className: 'main-view' },
        _react2.default.createElement(_FlowTable2.default, null),
        hasSelection && _react2.default.createElement(_Splitter2.default, { key: 'splitter' }),
        hasSelection && _react2.default.createElement(_FlowView2.default, { key: 'flowDetails' })
    );
}

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        hasSelection: !!state.flows.byId[state.flows.selected[0]]
    };
}, {})(MainView);

},{"./FlowTable":17,"./FlowView":21,"./common/Splitter":51,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],38:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _reactRedux = require('react-redux');

var _ModalList = require('./ModalList');

var _ModalList2 = _interopRequireDefault(_ModalList);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var PureModal = function (_Component) {
    _inherits(PureModal, _Component);

    function PureModal(props, context) {
        _classCallCheck(this, PureModal);

        return _possibleConstructorReturn(this, (PureModal.__proto__ || Object.getPrototypeOf(PureModal)).call(this, props, context));
    }

    _createClass(PureModal, [{
        key: 'render',
        value: function render() {
            var activeModal = this.props.activeModal;

            var ActiveModal = _ModalList2.default.find(function (m) {
                return m.name === activeModal;
            });
            return activeModal ? _react2.default.createElement(ActiveModal, null) : _react2.default.createElement('div', null);
        }
    }]);

    return PureModal;
}(_react.Component);

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        activeModal: state.ui.modal.activeModal
    };
})(PureModal);

},{"./ModalList":40,"react":"react","react-redux":"react-redux"}],39:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = ModalLayout;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function ModalLayout(_ref) {
    var children = _ref.children;

    return _react2.default.createElement(
        "div",
        null,
        _react2.default.createElement("div", { className: "modal-backdrop fade in" }),
        _react2.default.createElement(
            "div",
            { className: "modal modal-visible", id: "optionsModal", tabIndex: "-1", role: "dialog", "aria-labelledby": "options" },
            _react2.default.createElement(
                "div",
                { className: "modal-dialog modal-lg", role: "document" },
                _react2.default.createElement(
                    "div",
                    { className: "modal-content" },
                    children
                )
            )
        )
    );
}

},{"react":"react"}],40:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _ModalLayout = require('./ModalLayout');

var _ModalLayout2 = _interopRequireDefault(_ModalLayout);

var _OptionModal = require('./OptionModal');

var _OptionModal2 = _interopRequireDefault(_OptionModal);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function OptionModal() {
    return _react2.default.createElement(
        _ModalLayout2.default,
        null,
        _react2.default.createElement(_OptionModal2.default, null)
    );
}

exports.default = [OptionModal];

},{"./ModalLayout":39,"./OptionModal":42,"react":"react"}],41:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.Options = exports.ChoicesOption = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require("react-redux");

var _options = require("../../ducks/options");

var _utils = require("../../utils");

var _classnames = require("classnames");

var _classnames2 = _interopRequireDefault(_classnames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

var stopPropagation = function stopPropagation(e) {
    if (e.keyCode !== _utils.Key.ESC) {
        e.stopPropagation();
    }
};

BooleanOption.PropTypes = {
    value: _propTypes2.default.bool.isRequired,
    onChange: _propTypes2.default.func.isRequired
};
function BooleanOption(_ref) {
    var value = _ref.value,
        _onChange = _ref.onChange,
        props = _objectWithoutProperties(_ref, ["value", "onChange"]);

    return _react2.default.createElement(
        "div",
        { className: "checkbox" },
        _react2.default.createElement(
            "label",
            null,
            _react2.default.createElement("input", _extends({ type: "checkbox",
                checked: value,
                onChange: function onChange(e) {
                    return _onChange(e.target.checked);
                }
            }, props)),
            "Enable"
        )
    );
}

StringOption.PropTypes = {
    value: _propTypes2.default.string.isRequired,
    onChange: _propTypes2.default.func.isRequired
};
function StringOption(_ref2) {
    var value = _ref2.value,
        _onChange2 = _ref2.onChange,
        props = _objectWithoutProperties(_ref2, ["value", "onChange"]);

    return _react2.default.createElement("input", _extends({ type: "text",
        value: value || "",
        onChange: function onChange(e) {
            return _onChange2(e.target.value);
        }
    }, props));
}
function Optional(Component) {
    return function (_ref3) {
        var _onChange3 = _ref3.onChange,
            props = _objectWithoutProperties(_ref3, ["onChange"]);

        return _react2.default.createElement(Component, _extends({
            onChange: function onChange(x) {
                return _onChange3(x ? x : null);
            }
        }, props));
    };
}

NumberOption.PropTypes = {
    value: _propTypes2.default.number.isRequired,
    onChange: _propTypes2.default.func.isRequired
};
function NumberOption(_ref4) {
    var value = _ref4.value,
        _onChange4 = _ref4.onChange,
        props = _objectWithoutProperties(_ref4, ["value", "onChange"]);

    return _react2.default.createElement("input", _extends({ type: "number",
        value: value,
        onChange: function onChange(e) {
            return _onChange4(parseInt(e.target.value));
        }
    }, props));
}

ChoicesOption.PropTypes = {
    value: _propTypes2.default.string.isRequired,
    onChange: _propTypes2.default.func.isRequired
};
function ChoicesOption(_ref5) {
    var value = _ref5.value,
        _onChange5 = _ref5.onChange,
        choices = _ref5.choices,
        props = _objectWithoutProperties(_ref5, ["value", "onChange", "choices"]);

    return _react2.default.createElement(
        "select",
        _extends({
            onChange: function onChange(e) {
                return _onChange5(e.target.value);
            },
            value: value
        }, props),
        choices.map(function (choice) {
            return _react2.default.createElement(
                "option",
                { key: choice, value: choice },
                choice
            );
        })
    );
}

exports.ChoicesOption = ChoicesOption;
StringSequenceOption.PropTypes = {
    value: _propTypes2.default.string.isRequired,
    onChange: _propTypes2.default.func.isRequired
};
function StringSequenceOption(_ref6) {
    var value = _ref6.value,
        _onChange6 = _ref6.onChange,
        props = _objectWithoutProperties(_ref6, ["value", "onChange"]);

    var height = Math.max(value.length, 1);
    return _react2.default.createElement("textarea", _extends({
        rows: height,
        value: value.join('\n'),
        onChange: function onChange(e) {
            return _onChange6(e.target.value.split("\n"));
        }
    }, props));
}

var Options = exports.Options = {
    "bool": BooleanOption,
    "str": StringOption,
    "int": NumberOption,
    "optional str": Optional(StringOption),
    "sequence of str": StringSequenceOption
};

function PureOption(_ref7) {
    var choices = _ref7.choices,
        type = _ref7.type,
        value = _ref7.value,
        onChange = _ref7.onChange,
        name = _ref7.name,
        error = _ref7.error;

    var Opt = void 0,
        props = {};
    if (choices) {
        Opt = ChoicesOption;
        props.choices = choices;
    } else {
        Opt = Options[type];
    }
    if (Opt !== BooleanOption) {
        props.className = "form-control";
    }

    return _react2.default.createElement(
        "div",
        { className: (0, _classnames2.default)({ 'has-error': error }) },
        _react2.default.createElement(Opt, _extends({
            name: name,
            value: value,
            onChange: onChange,
            onKeyDown: stopPropagation
        }, props))
    );
}
exports.default = (0, _reactRedux.connect)(function (state, _ref8) {
    var name = _ref8.name;
    return _extends({}, state.options[name], state.ui.optionsEditor[name]);
}, function (dispatch, _ref9) {
    var name = _ref9.name;
    return {
        onChange: function onChange(value) {
            return dispatch((0, _options.update)(name, value));
        }
    };
})(PureOption);

},{"../../ducks/options":59,"../../utils":71,"classnames":"classnames","prop-types":"prop-types","react":"react","react-redux":"react-redux"}],42:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

exports.PureOptionDefault = PureOptionDefault;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _reactRedux = require("react-redux");

var _modal = require("../../ducks/ui/modal");

var modalAction = _interopRequireWildcard(_modal);

var _options = require("../../ducks/options");

var optionAction = _interopRequireWildcard(_options);

var _Option = require("./Option");

var _Option2 = _interopRequireDefault(_Option);

var _lodash = require("lodash");

var _lodash2 = _interopRequireDefault(_lodash);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function PureOptionHelp(_ref) {
    var help = _ref.help;

    return _react2.default.createElement(
        "div",
        { className: "help-block small" },
        help
    );
}
var OptionHelp = (0, _reactRedux.connect)(function (state, _ref2) {
    var name = _ref2.name;
    return {
        help: state.options[name].help
    };
})(PureOptionHelp);

function PureOptionError(_ref3) {
    var error = _ref3.error;

    if (!error) return null;
    return _react2.default.createElement(
        "div",
        { className: "small text-danger" },
        error
    );
}
var OptionError = (0, _reactRedux.connect)(function (state, _ref4) {
    var name = _ref4.name;
    return {
        error: state.ui.optionsEditor[name] && state.ui.optionsEditor[name].error
    };
})(PureOptionError);

function PureOptionDefault(_ref5) {
    var value = _ref5.value,
        defaultVal = _ref5.defaultVal;

    if (value === defaultVal) {
        return null;
    } else {
        if (typeof defaultVal === 'boolean') {
            defaultVal = defaultVal ? 'true' : 'false';
        } else if (Array.isArray(defaultVal)) {
            if (_lodash2.default.isEmpty(_lodash2.default.compact(value)) && // filter the empty string in array
            _lodash2.default.isEmpty(defaultVal)) {
                return null;
            }
            defaultVal = '[ ]';
        } else if (defaultVal === '') {
            defaultVal = '\"\"';
        } else if (defaultVal === null) {
            defaultVal = 'null';
        }
        return _react2.default.createElement(
            "div",
            { className: "small" },
            "Default: ",
            _react2.default.createElement(
                "strong",
                null,
                " ",
                defaultVal,
                " "
            ),
            " "
        );
    }
}
var OptionDefault = (0, _reactRedux.connect)(function (state, _ref6) {
    var name = _ref6.name;
    return {
        value: state.options[name].value,
        defaultVal: state.options[name].default
    };
})(PureOptionDefault);

var PureOptionModal = function (_Component) {
    _inherits(PureOptionModal, _Component);

    function PureOptionModal(props, context) {
        _classCallCheck(this, PureOptionModal);

        var _this = _possibleConstructorReturn(this, (PureOptionModal.__proto__ || Object.getPrototypeOf(PureOptionModal)).call(this, props, context));

        _this.state = { title: 'Options' };
        return _this;
    }

    _createClass(PureOptionModal, [{
        key: "componentWillUnmount",
        value: function componentWillUnmount() {
            // this.props.save()
        }
    }, {
        key: "render",
        value: function render() {
            var _props = this.props,
                hideModal = _props.hideModal,
                options = _props.options;
            var title = this.state.title;

            return _react2.default.createElement(
                "div",
                null,
                _react2.default.createElement(
                    "div",
                    { className: "modal-header" },
                    _react2.default.createElement(
                        "button",
                        { type: "button", className: "close", "data-dismiss": "modal", onClick: function onClick() {
                                hideModal();
                            } },
                        _react2.default.createElement("i", { className: "fa fa-fw fa-times" })
                    ),
                    _react2.default.createElement(
                        "div",
                        { className: "modal-title" },
                        _react2.default.createElement(
                            "h4",
                            null,
                            title
                        )
                    )
                ),
                _react2.default.createElement(
                    "div",
                    { className: "modal-body" },
                    _react2.default.createElement(
                        "div",
                        { className: "form-horizontal" },
                        options.map(function (name) {
                            return _react2.default.createElement(
                                "div",
                                { key: name, className: "form-group" },
                                _react2.default.createElement(
                                    "div",
                                    { className: "col-xs-6" },
                                    _react2.default.createElement(
                                        "label",
                                        { htmlFor: name },
                                        name
                                    ),
                                    _react2.default.createElement(OptionHelp, { name: name })
                                ),
                                _react2.default.createElement(
                                    "div",
                                    { className: "col-xs-6" },
                                    _react2.default.createElement(_Option2.default, { name: name }),
                                    _react2.default.createElement(OptionError, { name: name }),
                                    _react2.default.createElement(OptionDefault, { name: name })
                                )
                            );
                        })
                    )
                ),
                _react2.default.createElement("div", { className: "modal-footer" })
            );
        }
    }]);

    return PureOptionModal;
}(_react.Component);

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        options: Object.keys(state.options).sort()
    };
}, {
    hideModal: modalAction.hideModal,
    save: optionAction.save
})(PureOptionModal);

},{"../../ducks/options":59,"../../ducks/ui/modal":65,"./Option":41,"lodash":"lodash","react":"react","react-redux":"react-redux"}],43:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _reactRedux = require('react-redux');

var _keyboard = require('../ducks/ui/keyboard');

var _MainView = require('./MainView');

var _MainView2 = _interopRequireDefault(_MainView);

var _Header = require('./Header');

var _Header2 = _interopRequireDefault(_Header);

var _EventLog = require('./EventLog');

var _EventLog2 = _interopRequireDefault(_EventLog);

var _Footer = require('./Footer');

var _Footer2 = _interopRequireDefault(_Footer);

var _Modal = require('./Modal/Modal');

var _Modal2 = _interopRequireDefault(_Modal);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var ProxyAppMain = function (_Component) {
    _inherits(ProxyAppMain, _Component);

    function ProxyAppMain() {
        _classCallCheck(this, ProxyAppMain);

        return _possibleConstructorReturn(this, (ProxyAppMain.__proto__ || Object.getPrototypeOf(ProxyAppMain)).apply(this, arguments));
    }

    _createClass(ProxyAppMain, [{
        key: 'componentWillMount',
        value: function componentWillMount() {
            window.addEventListener('keydown', this.props.onKeyDown);
        }
    }, {
        key: 'componentWillUnmount',
        value: function componentWillUnmount() {
            window.removeEventListener('keydown', this.props.onKeyDown);
        }
    }, {
        key: 'render',
        value: function render() {
            var showEventLog = this.props.showEventLog;

            return _react2.default.createElement(
                'div',
                { id: 'container', tabIndex: '0' },
                _react2.default.createElement(_Header2.default, null),
                _react2.default.createElement(_MainView2.default, null),
                showEventLog && _react2.default.createElement(_EventLog2.default, { key: 'eventlog' }),
                _react2.default.createElement(_Footer2.default, null),
                _react2.default.createElement(_Modal2.default, null)
            );
        }
    }]);

    return ProxyAppMain;
}(_react.Component);

exports.default = (0, _reactRedux.connect)(function (state) {
    return {
        showEventLog: state.eventLog.visible
    };
}, {
    onKeyDown: _keyboard.onKeyDown
})(ProxyAppMain);

},{"../ducks/ui/keyboard":64,"./EventLog":15,"./Footer":27,"./Header":28,"./MainView":37,"./Modal/Modal":38,"prop-types":"prop-types","react":"react","react-redux":"react-redux"}],44:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _ValueEditor = require('./ValueEditor');

var _ValueEditor2 = _interopRequireDefault(_ValueEditor);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var ValidateEditor = function (_Component) {
    _inherits(ValidateEditor, _Component);

    function ValidateEditor(props) {
        _classCallCheck(this, ValidateEditor);

        var _this = _possibleConstructorReturn(this, (ValidateEditor.__proto__ || Object.getPrototypeOf(ValidateEditor)).call(this, props));

        _this.state = { valid: props.isValid(props.content) };
        _this.onInput = _this.onInput.bind(_this);
        _this.onDone = _this.onDone.bind(_this);
        return _this;
    }

    _createClass(ValidateEditor, [{
        key: 'componentWillReceiveProps',
        value: function componentWillReceiveProps(nextProps) {
            this.setState({ valid: nextProps.isValid(nextProps.content) });
        }
    }, {
        key: 'onInput',
        value: function onInput(content) {
            this.setState({ valid: this.props.isValid(content) });
        }
    }, {
        key: 'onDone',
        value: function onDone(content) {
            if (!this.props.isValid(content)) {
                this.editor.reset();
                content = this.props.content;
            }
            this.props.onDone(content);
        }
    }, {
        key: 'render',
        value: function render() {
            var _this2 = this;

            var className = (0, _classnames2.default)(this.props.className, {
                'has-success': this.state.valid,
                'has-warning': !this.state.valid
            });
            return _react2.default.createElement(_ValueEditor2.default, {
                content: this.props.content,
                readonly: this.props.readonly,
                onDone: this.onDone,
                onInput: this.onInput,
                className: className,
                ref: function ref(e) {
                    return _this2.editor = e;
                }
            });
        }
    }]);

    return ValidateEditor;
}(_react.Component);

ValidateEditor.propTypes = {
    content: _propTypes2.default.string.isRequired,
    readonly: _propTypes2.default.bool,
    onDone: _propTypes2.default.func.isRequired,
    className: _propTypes2.default.string,
    isValid: _propTypes2.default.func.isRequired
};
exports.default = ValidateEditor;

},{"./ValueEditor":45,"classnames":"classnames","prop-types":"prop-types","react":"react"}],45:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

var _utils = require('../../utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var ValueEditor = function (_Component) {
    _inherits(ValueEditor, _Component);

    function ValueEditor(props) {
        _classCallCheck(this, ValueEditor);

        var _this = _possibleConstructorReturn(this, (ValueEditor.__proto__ || Object.getPrototypeOf(ValueEditor)).call(this, props));

        _this.state = { editable: false };

        _this.onPaste = _this.onPaste.bind(_this);
        _this.onMouseDown = _this.onMouseDown.bind(_this);
        _this.onMouseUp = _this.onMouseUp.bind(_this);
        _this.onFocus = _this.onFocus.bind(_this);
        _this.onClick = _this.onClick.bind(_this);
        _this.blur = _this.blur.bind(_this);
        _this.onBlur = _this.onBlur.bind(_this);
        _this.reset = _this.reset.bind(_this);
        _this.onKeyDown = _this.onKeyDown.bind(_this);
        _this.onInput = _this.onInput.bind(_this);
        return _this;
    }

    _createClass(ValueEditor, [{
        key: 'blur',
        value: function blur() {
            // a stop would cause a blur as a side-effect.
            // but a blur event must trigger a stop as well.
            // to fix this, make stop = blur and do the actual stop in the onBlur handler.
            this.input.blur();
        }
    }, {
        key: 'reset',
        value: function reset() {
            this.input.innerHTML = _lodash2.default.escape(this.props.content);
        }
    }, {
        key: 'render',
        value: function render() {
            var _this2 = this;

            var className = (0, _classnames2.default)('inline-input', {
                'readonly': this.props.readonly,
                'editable': !this.props.readonly
            }, this.props.className);
            return _react2.default.createElement('div', {
                ref: function ref(input) {
                    return _this2.input = input;
                },
                tabIndex: this.props.readonly ? undefined : 0,
                className: className,
                contentEditable: this.state.editable || undefined,
                onFocus: this.onFocus,
                onMouseDown: this.onMouseDown,
                onClick: this.onClick,
                onBlur: this.onBlur,
                onKeyDown: this.onKeyDown,
                onInput: this.onInput,
                onPaste: this.onPaste,
                dangerouslySetInnerHTML: { __html: _lodash2.default.escape(this.props.content) }
            });
        }
    }, {
        key: 'onPaste',
        value: function onPaste(e) {
            e.preventDefault();
            var content = e.clipboardData.getData('text/plain');
            document.execCommand('insertHTML', false, content);
        }
    }, {
        key: 'onMouseDown',
        value: function onMouseDown(e) {
            this._mouseDown = true;
            window.addEventListener('mouseup', this.onMouseUp);
        }
    }, {
        key: 'onMouseUp',
        value: function onMouseUp() {
            if (this._mouseDown) {
                this._mouseDown = false;
                window.removeEventListener('mouseup', this.onMouseUp);
            }
        }
    }, {
        key: 'onClick',
        value: function onClick(e) {
            this.onMouseUp();
            this.onFocus(e);
        }
    }, {
        key: 'onFocus',
        value: function onFocus(e) {
            var _this3 = this;

            if (this._mouseDown || this._ignore_events || this.state.editable || this.props.readonly) {
                return;
            }

            // contenteditable in FireFox is more or less broken.
            // - we need to blur() and then focus(), otherwise the caret is not shown.
            // - blur() + focus() == we need to save the caret position before
            //   Firefox sometimes just doesn't set a caret position => use caretPositionFromPoint
            var sel = window.getSelection();
            var range = void 0;
            if (sel.rangeCount > 0) {
                range = sel.getRangeAt(0);
            } else if (document.caretPositionFromPoint && e.clientX && e.clientY) {
                var pos = document.caretPositionFromPoint(e.clientX, e.clientY);
                range = document.createRange();
                range.setStart(pos.offsetNode, pos.offset);
            } else if (document.caretRangeFromPoint && e.clientX && e.clientY) {
                range = document.caretRangeFromPoint(e.clientX, e.clientY);
            } else {
                range = document.createRange();
                range.selectNodeContents(this.input);
            }

            this._ignore_events = true;
            this.setState({ editable: true }, function () {
                _this3.input.blur();
                _this3.input.focus();
                _this3._ignore_events = false;
                range.selectNodeContents(_this3.input);
                sel.removeAllRanges();
                sel.addRange(range);
            });
        }
    }, {
        key: 'onBlur',
        value: function onBlur(e) {
            if (this._ignore_events || this.props.readonly) {
                return;
            }
            window.getSelection().removeAllRanges(); //make sure that selection is cleared on blur
            this.setState({ editable: false });
            this.props.onDone(this.input.textContent);
        }
    }, {
        key: 'onKeyDown',
        value: function onKeyDown(e) {
            e.stopPropagation();
            switch (e.keyCode) {
                case _utils.Key.ESC:
                    e.preventDefault();
                    this.reset();
                    this.blur();
                    break;
                case _utils.Key.ENTER:
                    if (!e.shiftKey) {
                        e.preventDefault();
                        this.blur();
                    }
                    break;
                default:
                    break;
            }
            this.props.onKeyDown(e);
        }
    }, {
        key: 'onInput',
        value: function onInput() {
            this.props.onInput(this.input.textContent);
        }
    }]);

    return ValueEditor;
}(_react.Component);

ValueEditor.propTypes = {
    content: _propTypes2.default.string.isRequired,
    readonly: _propTypes2.default.bool,
    onDone: _propTypes2.default.func.isRequired,
    className: _propTypes2.default.string,
    onInput: _propTypes2.default.func,
    onKeyDown: _propTypes2.default.func
};
ValueEditor.defaultProps = {
    onInput: function onInput() {},
    onKeyDown: function onKeyDown() {}
};
exports.default = ValueEditor;

},{"../../utils":71,"classnames":"classnames","lodash":"lodash","prop-types":"prop-types","react":"react"}],46:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = Button;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

var _classnames = require("classnames");

var _classnames2 = _interopRequireDefault(_classnames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

Button.propTypes = {
    onClick: _propTypes2.default.func.isRequired,
    children: _propTypes2.default.node.isRequired,
    icon: _propTypes2.default.string,
    title: _propTypes2.default.string
};

function Button(_ref) {
    var onClick = _ref.onClick,
        children = _ref.children,
        icon = _ref.icon,
        disabled = _ref.disabled,
        className = _ref.className,
        title = _ref.title;

    return _react2.default.createElement(
        "div",
        { className: (0, _classnames2.default)(className, 'btn btn-default'),
            onClick: disabled ? undefined : onClick,
            disabled: disabled,
            title: title },
        icon && _react2.default.createElement("i", { className: "fa fa-fw " + icon }),
        children
    );
}

},{"classnames":"classnames","prop-types":"prop-types","react":"react"}],47:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = DocsLink;

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _propTypes = require("prop-types");

var _propTypes2 = _interopRequireDefault(_propTypes);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

DocsLink.propTypes = {
    resource: _propTypes2.default.string.isRequired
};

function DocsLink(_ref) {
    var children = _ref.children,
        resource = _ref.resource;

    var url = "https://docs.mitmproxy.org/stable/" + resource;
    return _react2.default.createElement(
        "a",
        { target: "_blank", href: url },
        children || _react2.default.createElement("i", { className: "fa fa-question-circle" })
    );
}

},{"prop-types":"prop-types","react":"react"}],48:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.Divider = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Divider = exports.Divider = function Divider() {
    return _react2.default.createElement('hr', { className: 'divider' });
};

var Dropdown = function (_Component) {
    _inherits(Dropdown, _Component);

    function Dropdown(props, context) {
        _classCallCheck(this, Dropdown);

        var _this = _possibleConstructorReturn(this, (Dropdown.__proto__ || Object.getPrototypeOf(Dropdown)).call(this, props, context));

        _this.state = { open: false };
        _this.close = _this.close.bind(_this);
        _this.open = _this.open.bind(_this);
        return _this;
    }

    _createClass(Dropdown, [{
        key: 'close',
        value: function close() {
            this.setState({ open: false });
            document.removeEventListener('click', this.close);
        }
    }, {
        key: 'open',
        value: function open(e) {
            e.preventDefault();
            if (this.state.open) {
                return;
            }
            this.setState({ open: !this.state.open });
            document.addEventListener('click', this.close);
        }
    }, {
        key: 'render',
        value: function render() {
            var _props = this.props,
                dropup = _props.dropup,
                className = _props.className,
                btnClass = _props.btnClass,
                text = _props.text,
                children = _props.children;

            return _react2.default.createElement(
                'div',
                { className: (0, _classnames2.default)(dropup ? 'dropup' : 'dropdown', className, { show: this.state.open }) },
                _react2.default.createElement(
                    'a',
                    { href: '#', className: btnClass,
                        onClick: this.open },
                    text
                ),
                _react2.default.createElement(
                    'ul',
                    { className: (0, _classnames2.default)("dropdown-menu", { show: this.state.open }), role: 'menu' },
                    children.map(function (item, i) {
                        return _react2.default.createElement(
                            'li',
                            { key: i },
                            ' ',
                            item,
                            ' '
                        );
                    })
                )
            );
        }
    }]);

    return Dropdown;
}(_react.Component);

Dropdown.propTypes = {
    dropup: _propTypes2.default.bool,
    className: _propTypes2.default.string,
    btnClass: _propTypes2.default.string.isRequired
};
Dropdown.defaultProps = {
    dropup: false
};
exports.default = Dropdown;

},{"classnames":"classnames","prop-types":"prop-types","react":"react"}],49:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = FileChooser;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

FileChooser.propTypes = {
    icon: _propTypes2.default.string,
    text: _propTypes2.default.string,
    className: _propTypes2.default.string,
    title: _propTypes2.default.string,
    onOpenFile: _propTypes2.default.func.isRequired
};

function FileChooser(_ref) {
    var icon = _ref.icon,
        text = _ref.text,
        className = _ref.className,
        title = _ref.title,
        onOpenFile = _ref.onOpenFile;

    var fileInput = void 0;
    return _react2.default.createElement(
        'a',
        { href: '#', onClick: function onClick() {
                return fileInput.click();
            },
            className: className,
            title: title },
        _react2.default.createElement('i', { className: 'fa fa-fw ' + icon }),
        text,
        _react2.default.createElement('input', {
            ref: function ref(_ref2) {
                return fileInput = _ref2;
            },
            className: 'hidden',
            type: 'file',
            onChange: function onChange(e) {
                e.preventDefault();if (e.target.files.length > 0) onOpenFile(e.target.files[0]);fileInput.value = "";
            }
        })
    );
}

},{"prop-types":"prop-types","react":"react"}],50:[function(require,module,exports){
(function (global){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = HideInStatic;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function HideInStatic(_ref) {
    var children = _ref.children;

    return global.MITMWEB_STATIC ? null : [children];
}

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"react":"react"}],51:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _reactDom = require('react-dom');

var _reactDom2 = _interopRequireDefault(_reactDom);

var _classnames = require('classnames');

var _classnames2 = _interopRequireDefault(_classnames);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Splitter = function (_Component) {
    _inherits(Splitter, _Component);

    function Splitter(props, context) {
        _classCallCheck(this, Splitter);

        var _this = _possibleConstructorReturn(this, (Splitter.__proto__ || Object.getPrototypeOf(Splitter)).call(this, props, context));

        _this.state = { applied: false, startX: false, startY: false };

        _this.onMouseMove = _this.onMouseMove.bind(_this);
        _this.onMouseDown = _this.onMouseDown.bind(_this);
        _this.onMouseUp = _this.onMouseUp.bind(_this);
        _this.onDragEnd = _this.onDragEnd.bind(_this);
        return _this;
    }

    _createClass(Splitter, [{
        key: 'onMouseDown',
        value: function onMouseDown(e) {
            this.setState({ startX: e.pageX, startY: e.pageY });

            window.addEventListener('mousemove', this.onMouseMove);
            window.addEventListener('mouseup', this.onMouseUp);
            // Occasionally, only a dragEnd event is triggered, but no mouseUp.
            window.addEventListener('dragend', this.onDragEnd);
        }
    }, {
        key: 'onDragEnd',
        value: function onDragEnd() {
            _reactDom2.default.findDOMNode(this).style.transform = '';

            window.removeEventListener('dragend', this.onDragEnd);
            window.removeEventListener('mouseup', this.onMouseUp);
            window.removeEventListener('mousemove', this.onMouseMove);
        }
    }, {
        key: 'onMouseUp',
        value: function onMouseUp(e) {
            this.onDragEnd();

            var node = _reactDom2.default.findDOMNode(this);
            var prev = node.previousElementSibling;

            var flexBasis = prev.offsetHeight + e.pageY - this.state.startY;

            if (this.props.axis === 'x') {
                flexBasis = prev.offsetWidth + e.pageX - this.state.startX;
            }

            prev.style.flex = '0 0 ' + Math.max(0, flexBasis) + 'px';
            node.nextElementSibling.style.flex = '1 1 auto';

            this.setState({ applied: true });
            this.onResize();
        }
    }, {
        key: 'onMouseMove',
        value: function onMouseMove(e) {
            var dX = 0;
            var dY = 0;
            if (this.props.axis === 'x') {
                dX = e.pageX - this.state.startX;
            } else {
                dY = e.pageY - this.state.startY;
            }
            _reactDom2.default.findDOMNode(this).style.transform = 'translate(' + dX + 'px, ' + dY + 'px)';
        }
    }, {
        key: 'onResize',
        value: function onResize() {
            // Trigger a global resize event. This notifies components that employ virtual scrolling
            // that their viewport may have changed.
            window.setTimeout(function () {
                return window.dispatchEvent(new CustomEvent('resize'));
            }, 1);
        }
    }, {
        key: 'reset',
        value: function reset(willUnmount) {
            if (!this.state.applied) {
                return;
            }

            var node = _reactDom2.default.findDOMNode(this);

            node.previousElementSibling.style.flex = '';
            node.nextElementSibling.style.flex = '';

            if (!willUnmount) {
                this.setState({ applied: false });
            }
            this.onResize();
        }
    }, {
        key: 'componentWillUnmount',
        value: function componentWillUnmount() {
            this.reset(true);
        }
    }, {
        key: 'render',
        value: function render() {
            return _react2.default.createElement(
                'div',
                { className: (0, _classnames2.default)('splitter', this.props.axis === 'x' ? 'splitter-x' : 'splitter-y') },
                _react2.default.createElement('div', { onMouseDown: this.onMouseDown, draggable: 'true' })
            );
        }
    }]);

    return Splitter;
}(_react.Component);

Splitter.defaultProps = { axis: 'x' };
exports.default = Splitter;

},{"classnames":"classnames","react":"react","react-dom":"react-dom"}],52:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = ToggleButton;

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

var _propTypes = require('prop-types');

var _propTypes2 = _interopRequireDefault(_propTypes);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

ToggleButton.propTypes = {
    checked: _propTypes2.default.bool.isRequired,
    onToggle: _propTypes2.default.func.isRequired,
    text: _propTypes2.default.string.isRequired
};

function ToggleButton(_ref) {
    var checked = _ref.checked,
        onToggle = _ref.onToggle,
        text = _ref.text;

    return _react2.default.createElement(
        'div',
        { className: "btn btn-toggle " + (checked ? "btn-primary" : "btn-default"), onClick: onToggle },
        _react2.default.createElement('i', { className: "fa fa-fw " + (checked ? "fa-check-square-o" : "fa-square-o") }),
        '\xA0',
        text
    );
}

},{"prop-types":"prop-types","react":"react"}],53:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _get = function get(object, property, receiver) { if (object === null) object = Function.prototype; var desc = Object.getOwnPropertyDescriptor(object, property); if (desc === undefined) { var parent = Object.getPrototypeOf(object); if (parent === null) { return undefined; } else { return get(parent, property, receiver); } } else if ("value" in desc) { return desc.value; } else { var getter = desc.get; if (getter === undefined) { return undefined; } return getter.call(receiver); } };

var _react = require("react");

var _react2 = _interopRequireDefault(_react);

var _reactDom = require("react-dom");

var _reactDom2 = _interopRequireDefault(_reactDom);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var symShouldStick = Symbol("shouldStick");
var isAtBottom = function isAtBottom(v) {
    return v.scrollTop + v.clientHeight === v.scrollHeight;
};

exports.default = function (Component) {
    var _class, _temp;

    return Object.assign((_temp = _class = function (_Component) {
        _inherits(AutoScrollWrapper, _Component);

        function AutoScrollWrapper() {
            _classCallCheck(this, AutoScrollWrapper);

            return _possibleConstructorReturn(this, (AutoScrollWrapper.__proto__ || Object.getPrototypeOf(AutoScrollWrapper)).apply(this, arguments));
        }

        _createClass(AutoScrollWrapper, [{
            key: "componentWillUpdate",
            value: function componentWillUpdate() {
                var viewport = _reactDom2.default.findDOMNode(this);
                this[symShouldStick] = viewport.scrollTop && isAtBottom(viewport);
                _get(AutoScrollWrapper.prototype.__proto__ || Object.getPrototypeOf(AutoScrollWrapper.prototype), "componentWillUpdate", this) && _get(AutoScrollWrapper.prototype.__proto__ || Object.getPrototypeOf(AutoScrollWrapper.prototype), "componentWillUpdate", this).call(this);
            }
        }, {
            key: "componentDidUpdate",
            value: function componentDidUpdate() {
                var viewport = _reactDom2.default.findDOMNode(this);
                if (this[symShouldStick] && !isAtBottom(viewport)) {
                    viewport.scrollTop = viewport.scrollHeight;
                }
                _get(AutoScrollWrapper.prototype.__proto__ || Object.getPrototypeOf(AutoScrollWrapper.prototype), "componentDidUpdate", this) && _get(AutoScrollWrapper.prototype.__proto__ || Object.getPrototypeOf(AutoScrollWrapper.prototype), "componentDidUpdate", this).call(this);
            }
        }]);

        return AutoScrollWrapper;
    }(Component), _class.displayName = Component.name, _temp), Component);
};

},{"react":"react","react-dom":"react-dom"}],54:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.calcVScroll = calcVScroll;
/**
 * Calculate virtual scroll stuffs
 *
 * @param {?Object} opts Options for calculation
 *
 * @returns {Object} result
 *
 * __opts__ should have following properties:
 * - {number}         itemCount
 * - {number}         rowHeight
 * - {number}         viewportTop
 * - {number}         viewportHeight
 * - {Array<?number>} [itemHeights]
 *
 * __result__ have following properties:
 * - {number} start
 * - {number} end
 * - {number} paddingTop
 * - {number} paddingBottom
 */
function calcVScroll(opts) {
    if (!opts) {
        return { start: 0, end: 0, paddingTop: 0, paddingBottom: 0 };
    }

    var itemCount = opts.itemCount,
        rowHeight = opts.rowHeight,
        viewportTop = opts.viewportTop,
        viewportHeight = opts.viewportHeight,
        itemHeights = opts.itemHeights;

    var viewportBottom = viewportTop + viewportHeight;

    var start = 0;
    var end = 0;

    var paddingTop = 0;
    var paddingBottom = 0;

    if (itemHeights) {

        for (var i = 0, pos = 0; i < itemCount; i++) {
            var height = itemHeights[i] || rowHeight;

            if (pos <= viewportTop && i % 2 === 0) {
                paddingTop = pos;
                start = i;
            }

            if (pos <= viewportBottom) {
                end = i + 1;
            } else {
                paddingBottom += height;
            }

            pos += height;
        }
    } else {

        // Make sure that we start at an even row so that CSS `:nth-child(even)` is preserved
        start = Math.max(0, Math.floor(viewportTop / rowHeight) - 1) & ~1;
        end = Math.min(itemCount, start + Math.ceil(viewportHeight / rowHeight) + 2);

        // When a large trunk of elements is removed from the button, start may be far off the viewport.
        // To make this issue less severe, limit the top placeholder to the total number of rows.
        paddingTop = Math.min(start, itemCount) * rowHeight;
        paddingBottom = Math.max(0, itemCount - end) * rowHeight;
    }

    return { start: start, end: end, paddingTop: paddingTop, paddingBottom: paddingBottom };
}

},{}],55:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.default = reducer;
exports.startFetching = startFetching;
exports.connectionEstablished = connectionEstablished;
exports.connectionError = connectionError;
exports.setOffline = setOffline;
var ConnectionState = exports.ConnectionState = {
    INIT: Symbol("init"),
    FETCHING: Symbol("fetching"), // WebSocket is established, but still fetching resources.
    ESTABLISHED: Symbol("established"),
    ERROR: Symbol("error"),
    OFFLINE: Symbol("offline") // indicates that there is no live (websocket) backend.
};

var defaultState = {
    state: ConnectionState.INIT,
    message: null
};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case ConnectionState.ESTABLISHED:
        case ConnectionState.FETCHING:
        case ConnectionState.ERROR:
        case ConnectionState.OFFLINE:
            return {
                state: action.type,
                message: action.message
            };

        default:
            return state;
    }
}

function startFetching() {
    return { type: ConnectionState.FETCHING };
}

function connectionEstablished() {
    return { type: ConnectionState.ESTABLISHED };
}

function connectionError(message) {
    return { type: ConnectionState.ERROR, message: message };
}
function setOffline() {
    return { type: ConnectionState.OFFLINE };
}

},{}],56:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.TOGGLE_FILTER = exports.TOGGLE_VISIBILITY = exports.RECEIVE = exports.ADD = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reduce;
exports.toggleFilter = toggleFilter;
exports.toggleVisibility = toggleVisibility;
exports.add = add;

var _store = require("./utils/store");

var storeActions = _interopRequireWildcard(_store);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var ADD = exports.ADD = 'EVENTS_ADD';
var RECEIVE = exports.RECEIVE = 'EVENTS_RECEIVE';
var TOGGLE_VISIBILITY = exports.TOGGLE_VISIBILITY = 'EVENTS_TOGGLE_VISIBILITY';
var TOGGLE_FILTER = exports.TOGGLE_FILTER = 'EVENTS_TOGGLE_FILTER';

var defaultState = _extends({
    visible: false,
    filters: { debug: false, info: true, web: true, warn: true, error: true }
}, (0, storeActions.default)(undefined, {}));

function reduce() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case TOGGLE_VISIBILITY:
            return _extends({}, state, {
                visible: !state.visible
            });

        case TOGGLE_FILTER:
            var filters = _extends({}, state.filters, _defineProperty({}, action.filter, !state.filters[action.filter]));
            return _extends({}, state, {
                filters: filters
            }, (0, storeActions.default)(state, storeActions.setFilter(function (log) {
                return filters[log.level];
            })));

        case ADD:
        case RECEIVE:
            return _extends({}, state, (0, storeActions.default)(state, storeActions[action.cmd](action.data, function (log) {
                return state.filters[log.level];
            })));

        default:
            return state;
    }
}

function toggleFilter(filter) {
    return { type: TOGGLE_FILTER, filter: filter };
}

function toggleVisibility() {
    return { type: TOGGLE_VISIBILITY };
}

function add(message) {
    var level = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'web';

    var data = {
        id: Math.random().toString(),
        message: message,
        level: level
    };
    return {
        type: ADD,
        cmd: "add",
        data: data
    };
}

},{"./utils/store":67}],57:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.REQUEST_ACTION = exports.SET_HIGHLIGHT = exports.SET_SORT = exports.SET_FILTER = exports.SELECT = exports.RECEIVE = exports.REMOVE = exports.UPDATE = exports.ADD = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reduce;
exports.makeFilter = makeFilter;
exports.makeSort = makeSort;
exports.setFilter = setFilter;
exports.setHighlight = setHighlight;
exports.setSort = setSort;
exports.selectRelative = selectRelative;
exports.resume = resume;
exports.resumeAll = resumeAll;
exports.kill = kill;
exports.killAll = killAll;
exports.remove = remove;
exports.duplicate = duplicate;
exports.replay = replay;
exports.revert = revert;
exports.update = update;
exports.uploadContent = uploadContent;
exports.clear = clear;
exports.download = download;
exports.upload = upload;
exports.select = select;

var _utils = require("../utils");

var _store = require("./utils/store");

var storeActions = _interopRequireWildcard(_store);

var _filt = require("../filt/filt");

var _filt2 = _interopRequireDefault(_filt);

var _utils2 = require("../flow/utils");

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

var ADD = exports.ADD = 'FLOWS_ADD';
var UPDATE = exports.UPDATE = 'FLOWS_UPDATE';
var REMOVE = exports.REMOVE = 'FLOWS_REMOVE';
var RECEIVE = exports.RECEIVE = 'FLOWS_RECEIVE';
var SELECT = exports.SELECT = 'FLOWS_SELECT';
var SET_FILTER = exports.SET_FILTER = 'FLOWS_SET_FILTER';
var SET_SORT = exports.SET_SORT = 'FLOWS_SET_SORT';
var SET_HIGHLIGHT = exports.SET_HIGHLIGHT = 'FLOWS_SET_HIGHLIGHT';
var REQUEST_ACTION = exports.REQUEST_ACTION = 'FLOWS_REQUEST_ACTION';

var defaultState = _extends({
    highlight: null,
    filter: null,
    sort: { column: null, desc: false },
    selected: []
}, (0, storeActions.default)(undefined, {}));

function reduce() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case ADD:
        case UPDATE:
        case REMOVE:
        case RECEIVE:
            var storeAction = storeActions[action.cmd](action.data, makeFilter(state.filter), makeSort(state.sort));

            var selected = state.selected;
            if (action.type === REMOVE && state.selected.includes(action.data)) {
                if (state.selected.length > 1) {
                    selected = selected.filter(function (x) {
                        return x !== action.data;
                    });
                } else {
                    selected = [];
                    if (action.data in state.viewIndex && state.view.length > 1) {
                        var currentIndex = state.viewIndex[action.data],
                            nextSelection = void 0;
                        if (currentIndex === state.view.length - 1) {
                            // last row
                            nextSelection = state.view[currentIndex - 1];
                        } else {
                            nextSelection = state.view[currentIndex + 1];
                        }
                        selected.push(nextSelection.id);
                    }
                }
            }

            return _extends({}, state, {
                selected: selected
            }, (0, storeActions.default)(state, storeAction));

        case SET_FILTER:
            return _extends({}, state, {
                filter: action.filter
            }, (0, storeActions.default)(state, storeActions.setFilter(makeFilter(action.filter), makeSort(state.sort))));

        case SET_HIGHLIGHT:
            return _extends({}, state, {
                highlight: action.highlight
            });

        case SET_SORT:
            return _extends({}, state, {
                sort: action.sort
            }, (0, storeActions.default)(state, storeActions.setSort(makeSort(action.sort))));

        case SELECT:
            return _extends({}, state, {
                selected: action.flowIds
            });

        default:
            return state;
    }
}

var sortKeyFuns = {

    TLSColumn: function TLSColumn(flow) {
        return flow.request.scheme;
    },

    PathColumn: function PathColumn(flow) {
        return _utils2.RequestUtils.pretty_url(flow.request);
    },

    MethodColumn: function MethodColumn(flow) {
        return flow.request.method;
    },

    StatusColumn: function StatusColumn(flow) {
        return flow.response && flow.response.status_code;
    },

    TimeColumn: function TimeColumn(flow) {
        return flow.response && flow.response.timestamp_end - flow.request.timestamp_start;
    },

    SizeColumn: function SizeColumn(flow) {
        var total = flow.request.contentLength;
        if (flow.response) {
            total += flow.response.contentLength || 0;
        }
        return total;
    }
};

function makeFilter(filter) {
    if (!filter) {
        return;
    }
    return _filt2.default.parse(filter);
}

function makeSort(_ref) {
    var column = _ref.column,
        desc = _ref.desc;

    var sortKeyFun = sortKeyFuns[column];
    if (!sortKeyFun) {
        return;
    }
    return function (a, b) {
        var ka = sortKeyFun(a);
        var kb = sortKeyFun(b);
        if (ka > kb) {
            return desc ? -1 : 1;
        }
        if (ka < kb) {
            return desc ? 1 : -1;
        }
        return 0;
    };
}

function setFilter(filter) {
    return { type: SET_FILTER, filter: filter };
}

function setHighlight(highlight) {
    return { type: SET_HIGHLIGHT, highlight: highlight };
}

function setSort(column, desc) {
    return { type: SET_SORT, sort: { column: column, desc: desc } };
}

function selectRelative(flows, shift) {
    var currentSelectionIndex = flows.viewIndex[flows.selected[0]];
    var minIndex = 0;
    var maxIndex = flows.view.length - 1;
    var newIndex = void 0;
    if (currentSelectionIndex === undefined) {
        newIndex = shift < 0 ? minIndex : maxIndex;
    } else {
        newIndex = currentSelectionIndex + shift;
        newIndex = window.Math.max(newIndex, minIndex);
        newIndex = window.Math.min(newIndex, maxIndex);
    }
    var flow = flows.view[newIndex];
    return select(flow ? flow.id : undefined);
}

function resume(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/resume", { method: 'POST' });
    };
}

function resumeAll() {
    return function (dispatch) {
        return (0, _utils.fetchApi)('/flows/resume', { method: 'POST' });
    };
}

function kill(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/kill", { method: 'POST' });
    };
}

function killAll() {
    return function (dispatch) {
        return (0, _utils.fetchApi)('/flows/kill', { method: 'POST' });
    };
}

function remove(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id, { method: 'DELETE' });
    };
}

function duplicate(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/duplicate", { method: 'POST' });
    };
}

function replay(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/replay", { method: 'POST' });
    };
}

function revert(flow) {
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/revert", { method: 'POST' });
    };
}

function update(flow, data) {
    return function (dispatch) {
        return _utils.fetchApi.put("/flows/" + flow.id, data);
    };
}

function uploadContent(flow, file, type) {
    var body = new FormData();
    file = new window.Blob([file], { type: 'plain/text' });
    body.append('file', file);
    return function (dispatch) {
        return (0, _utils.fetchApi)("/flows/" + flow.id + "/" + type + "/content.data", { method: 'POST', body: body });
    };
}

function clear() {
    return function (dispatch) {
        return (0, _utils.fetchApi)('/clear', { method: 'POST' });
    };
}

function download() {
    window.location = '/flows/dump';
    return { type: REQUEST_ACTION };
}

function upload(file) {
    var body = new FormData();
    body.append('file', file);
    return function (dispatch) {
        return (0, _utils.fetchApi)('/flows/dump', { method: 'POST', body: body });
    };
}

function select(id) {
    return {
        type: SELECT,
        flowIds: id ? [id] : []
    };
}

},{"../filt/filt":68,"../flow/utils":69,"../utils":71,"./utils/store":67}],58:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _redux = require("redux");

var _eventLog = require("./eventLog");

var _eventLog2 = _interopRequireDefault(_eventLog);

var _flows = require("./flows");

var _flows2 = _interopRequireDefault(_flows);

var _settings = require("./settings");

var _settings2 = _interopRequireDefault(_settings);

var _index = require("./ui/index");

var _index2 = _interopRequireDefault(_index);

var _connection = require("./connection");

var _connection2 = _interopRequireDefault(_connection);

var _options = require("./options");

var _options2 = _interopRequireDefault(_options);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = (0, _redux.combineReducers)({
    eventLog: _eventLog2.default,
    flows: _flows2.default,
    settings: _settings2.default,
    connection: _connection2.default,
    ui: _index2.default,
    options: _options2.default
});

},{"./connection":55,"./eventLog":56,"./flows":57,"./options":59,"./settings":60,"./ui/index":63,"redux":"redux"}],59:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.REQUEST_UPDATE = exports.UPDATE = exports.RECEIVE = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.pureSendUpdate = pureSendUpdate;
exports.update = update;
exports.save = save;

var _utils = require("../utils");

var _optionsEditor = require("./ui/optionsEditor");

var optionsEditorActions = _interopRequireWildcard(_optionsEditor);

var _lodash = require("lodash");

var _lodash2 = _interopRequireDefault(_lodash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var RECEIVE = exports.RECEIVE = 'OPTIONS_RECEIVE';
var UPDATE = exports.UPDATE = 'OPTIONS_UPDATE';
var REQUEST_UPDATE = exports.REQUEST_UPDATE = 'REQUEST_UPDATE';

var defaultState = {};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case RECEIVE:
            return action.data;

        case UPDATE:
            return _extends({}, state, action.data);

        default:
            return state;
    }
}

function pureSendUpdate(option, value, dispatch) {
    _utils.fetchApi.put('/options', _defineProperty({}, option, value)).then(function (response) {
        if (response.status === 200) {
            dispatch(optionsEditorActions.updateSuccess(option));
        } else {
            response.text().then(function (error) {
                dispatch(optionsEditorActions.updateError(option, error));
            });
        }
    });
}
var sendUpdate = _lodash2.default.throttle(pureSendUpdate, 700, { leading: true, trailing: true });

function update(option, value) {
    return function (dispatch) {
        dispatch(optionsEditorActions.startUpdate(option, value));
        sendUpdate(option, value, dispatch);
    };
}

function save() {
    return function (dispatch) {
        return (0, _utils.fetchApi)('/options/save', { method: 'POST' });
    };
}

},{"../utils":71,"./ui/optionsEditor":66,"lodash":"lodash"}],60:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.REQUEST_UPDATE = exports.UPDATE = exports.RECEIVE = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.update = update;

var _utils = require('../utils');

var RECEIVE = exports.RECEIVE = 'SETTINGS_RECEIVE';
var UPDATE = exports.UPDATE = 'SETTINGS_UPDATE';
var REQUEST_UPDATE = exports.REQUEST_UPDATE = 'REQUEST_UPDATE';

var defaultState = {};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case RECEIVE:
            return action.data;

        case UPDATE:
            return _extends({}, state, action.data);

        default:
            return state;
    }
}

function update(settings) {
    _utils.fetchApi.put('/settings', settings);
    return { type: REQUEST_UPDATE };
}

},{"../utils":71}],61:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.SET_CONTENT = exports.SET_CONTENT_VIEW_DESCRIPTION = exports.SET_SHOW_FULL_CONTENT = exports.UPLOAD_CONTENT = exports.UPDATE_EDIT = exports.START_EDIT = exports.SET_TAB = exports.DISPLAY_LARGE = exports.SET_CONTENT_VIEW = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.setContentView = setContentView;
exports.displayLarge = displayLarge;
exports.selectTab = selectTab;
exports.startEdit = startEdit;
exports.updateEdit = updateEdit;
exports.setContentViewDescription = setContentViewDescription;
exports.setShowFullContent = setShowFullContent;
exports.setContent = setContent;
exports.stopEdit = stopEdit;

var _flows = require('../flows');

var flowsActions = _interopRequireWildcard(_flows);

var _utils = require('../../utils');

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

var SET_CONTENT_VIEW = exports.SET_CONTENT_VIEW = 'UI_FLOWVIEW_SET_CONTENT_VIEW',
    DISPLAY_LARGE = exports.DISPLAY_LARGE = 'UI_FLOWVIEW_DISPLAY_LARGE',
    SET_TAB = exports.SET_TAB = "UI_FLOWVIEW_SET_TAB",
    START_EDIT = exports.START_EDIT = 'UI_FLOWVIEW_START_EDIT',
    UPDATE_EDIT = exports.UPDATE_EDIT = 'UI_FLOWVIEW_UPDATE_EDIT',
    UPLOAD_CONTENT = exports.UPLOAD_CONTENT = 'UI_FLOWVIEW_UPLOAD_CONTENT',
    SET_SHOW_FULL_CONTENT = exports.SET_SHOW_FULL_CONTENT = 'UI_SET_SHOW_FULL_CONTENT',
    SET_CONTENT_VIEW_DESCRIPTION = exports.SET_CONTENT_VIEW_DESCRIPTION = "UI_SET_CONTENT_VIEW_DESCRIPTION",
    SET_CONTENT = exports.SET_CONTENT = "UI_SET_CONTENT";

var defaultState = {
    displayLarge: false,
    viewDescription: '',
    showFullContent: false,
    modifiedFlow: false,
    contentView: 'Auto',
    tab: 'request',
    content: [],
    maxContentLines: 80
};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    var wasInEditMode = state.modifiedFlow;

    var content = action.content || state.content;
    var isFullContentShown = content && content.length <= state.maxContentLines;

    switch (action.type) {

        case START_EDIT:
            return _extends({}, state, {
                modifiedFlow: action.flow,
                contentView: 'Edit',
                showFullContent: true
            });

        case UPDATE_EDIT:
            return _extends({}, state, {
                modifiedFlow: _lodash2.default.merge({}, state.modifiedFlow, action.update)
            });

        case flowsActions.SELECT:
            return _extends({}, state, {
                modifiedFlow: false,
                displayLarge: false,
                contentView: wasInEditMode ? 'Auto' : state.contentView,
                showFullContent: isFullContentShown
            });

        case flowsActions.UPDATE:
            // There is no explicit "stop edit" event.
            // We stop editing when we receive an update for
            // the currently edited flow from the server
            if (action.data.id === state.modifiedFlow.id) {
                return _extends({}, state, {
                    modifiedFlow: false,
                    displayLarge: false,
                    contentView: wasInEditMode ? 'Auto' : state.contentView,
                    showFullContent: false
                });
            } else {
                return state;
            }

        case SET_CONTENT_VIEW_DESCRIPTION:
            return _extends({}, state, {
                viewDescription: action.description
            });

        case SET_SHOW_FULL_CONTENT:
            return _extends({}, state, {
                showFullContent: true
            });

        case SET_TAB:
            return _extends({}, state, {
                tab: action.tab ? action.tab : 'request',
                displayLarge: false,
                showFullContent: state.contentView === 'Edit'
            });

        case SET_CONTENT_VIEW:
            return _extends({}, state, {
                contentView: action.contentView,
                showFullContent: action.contentView === 'Edit'
            });

        case SET_CONTENT:
            return _extends({}, state, {
                content: action.content,
                showFullContent: isFullContentShown
            });

        case DISPLAY_LARGE:
            return _extends({}, state, {
                displayLarge: true
            });
        default:
            return state;
    }
}

function setContentView(contentView) {
    return { type: SET_CONTENT_VIEW, contentView: contentView };
}

function displayLarge() {
    return { type: DISPLAY_LARGE };
}

function selectTab(tab) {
    return { type: SET_TAB, tab: tab };
}

function startEdit(flow) {
    return { type: START_EDIT, flow: flow };
}

function updateEdit(update) {
    return { type: UPDATE_EDIT, update: update };
}

function setContentViewDescription(description) {
    return { type: SET_CONTENT_VIEW_DESCRIPTION, description: description };
}

function setShowFullContent() {
    return { type: SET_SHOW_FULL_CONTENT };
}

function setContent(content) {
    return { type: SET_CONTENT, content: content };
}

function stopEdit(flow, modifiedFlow) {
    return flowsActions.update(flow, (0, _utils.getDiff)(flow, modifiedFlow));
}

},{"../../utils":71,"../flows":57,"lodash":"lodash"}],62:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.SET_ACTIVE_MENU = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.setActiveMenu = setActiveMenu;

var _flows = require('../flows');

var flowsActions = _interopRequireWildcard(_flows);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

var SET_ACTIVE_MENU = exports.SET_ACTIVE_MENU = 'UI_SET_ACTIVE_MENU';

var defaultState = {
    activeMenu: 'Start',
    isFlowSelected: false
};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case SET_ACTIVE_MENU:
            return _extends({}, state, {
                activeMenu: action.activeMenu
            });

        case flowsActions.SELECT:
            // First Select
            if (action.flowIds.length > 0 && !state.isFlowSelected) {
                return _extends({}, state, {
                    activeMenu: 'Flow',
                    isFlowSelected: true
                });
            }

            // Deselect
            if (action.flowIds.length === 0 && state.isFlowSelected) {
                var activeMenu = state.activeMenu;
                if (activeMenu === 'Flow') {
                    activeMenu = 'Start';
                }
                return _extends({}, state, {
                    activeMenu: activeMenu,
                    isFlowSelected: false
                });
            }
            return state;
        default:
            return state;
    }
}

function setActiveMenu(activeMenu) {
    return { type: SET_ACTIVE_MENU, activeMenu: activeMenu };
}

},{"../flows":57}],63:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _redux = require('redux');

var _flow = require('./flow');

var _flow2 = _interopRequireDefault(_flow);

var _header = require('./header');

var _header2 = _interopRequireDefault(_header);

var _modal = require('./modal');

var _modal2 = _interopRequireDefault(_modal);

var _optionsEditor = require('./optionsEditor');

var _optionsEditor2 = _interopRequireDefault(_optionsEditor);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// TODO: Just move ducks/ui/* into ducks/?
exports.default = (0, _redux.combineReducers)({
    flow: _flow2.default,
    header: _header2.default,
    modal: _modal2.default,
    optionsEditor: _optionsEditor2.default
});

},{"./flow":61,"./header":62,"./modal":65,"./optionsEditor":66,"redux":"redux"}],64:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.onKeyDown = onKeyDown;

var _utils = require("../../utils");

var _flow = require("./flow");

var _flows = require("../flows");

var flowsActions = _interopRequireWildcard(_flows);

var _modal = require("./modal");

var modalActions = _interopRequireWildcard(_modal);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function onKeyDown(e) {
    //console.debug("onKeyDown", e)
    if (e.ctrlKey || e.metaKey) {
        return function () {};
    }
    var key = e.keyCode,
        shiftKey = e.shiftKey;
    e.preventDefault();
    return function (dispatch, getState) {

        var flows = getState().flows,
            flow = flows.byId[getState().flows.selected[0]];

        switch (key) {
            case _utils.Key.K:
            case _utils.Key.UP:
                dispatch(flowsActions.selectRelative(flows, -1));
                break;

            case _utils.Key.J:
            case _utils.Key.DOWN:
                dispatch(flowsActions.selectRelative(flows, +1));
                break;

            case _utils.Key.SPACE:
            case _utils.Key.PAGE_DOWN:
                dispatch(flowsActions.selectRelative(flows, +10));
                break;

            case _utils.Key.PAGE_UP:
                dispatch(flowsActions.selectRelative(flows, -10));
                break;

            case _utils.Key.END:
                dispatch(flowsActions.selectRelative(flows, +1e10));
                break;

            case _utils.Key.HOME:
                dispatch(flowsActions.selectRelative(flows, -1e10));
                break;

            case _utils.Key.ESC:
                if (getState().ui.modal.activeModal) {
                    dispatch(modalActions.hideModal());
                } else {
                    dispatch(flowsActions.select(null));
                }
                break;

            case _utils.Key.LEFT:
                {
                    if (!flow) break;
                    var tabs = ['request', 'response', 'error'].filter(function (k) {
                        return flow[k];
                    }).concat(['details']),
                        currentTab = getState().ui.flow.tab,
                        nextTab = tabs[(tabs.indexOf(currentTab) - 1 + tabs.length) % tabs.length];
                    dispatch((0, _flow.selectTab)(nextTab));
                    break;
                }

            case _utils.Key.TAB:
            case _utils.Key.RIGHT:
                {
                    if (!flow) break;
                    var _tabs = ['request', 'response', 'error'].filter(function (k) {
                        return flow[k];
                    }).concat(['details']),
                        _currentTab = getState().ui.flow.tab,
                        _nextTab = _tabs[(_tabs.indexOf(_currentTab) + 1) % _tabs.length];
                    dispatch((0, _flow.selectTab)(_nextTab));
                    break;
                }

            case _utils.Key.D:
                {
                    if (!flow) {
                        return;
                    }
                    if (shiftKey) {
                        dispatch(flowsActions.duplicate(flow));
                    } else {
                        dispatch(flowsActions.remove(flow));
                    }
                    break;
                }

            case _utils.Key.A:
                {
                    if (shiftKey) {
                        dispatch(flowsActions.resumeAll());
                    } else if (flow && flow.intercepted) {
                        dispatch(flowsActions.resume(flow));
                    }
                    break;
                }

            case _utils.Key.R:
                {
                    if (!shiftKey && flow) {
                        dispatch(flowsActions.replay(flow));
                    }
                    break;
                }

            case _utils.Key.V:
                {
                    if (!shiftKey && flow && flow.modified) {
                        dispatch(flowsActions.revert(flow));
                    }
                    break;
                }

            case _utils.Key.X:
                {
                    if (shiftKey) {
                        dispatch(flowsActions.killAll());
                    } else if (flow && flow.intercepted) {
                        dispatch(flowsActions.kill(flow));
                    }
                    break;
                }

            case _utils.Key.Z:
                {
                    if (!shiftKey) {
                        dispatch(flowsActions.clear());
                    }
                    break;
                }

            default:
                return;
        }
    };
}

},{"../../utils":71,"../flows":57,"./flow":61,"./modal":65}],65:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.setActiveModal = setActiveModal;
exports.hideModal = hideModal;
var HIDE_MODAL = exports.HIDE_MODAL = 'UI_HIDE_MODAL';
var SET_ACTIVE_MODAL = exports.SET_ACTIVE_MODAL = 'UI_SET_ACTIVE_MODAL';

var defaultState = {
    activeModal: undefined
};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {

        case SET_ACTIVE_MODAL:
            return _extends({}, state, {
                activeModal: action.activeModal
            });

        case HIDE_MODAL:
            return _extends({}, state, {
                activeModal: undefined
            });
        default:
            return state;
    }
}

function setActiveModal(activeModal) {
    return { type: SET_ACTIVE_MODAL, activeModal: activeModal };
}

function hideModal() {
    return { type: HIDE_MODAL };
}

},{}],66:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.OPTION_UPDATE_ERROR = exports.OPTION_UPDATE_SUCCESS = exports.OPTION_UPDATE_START = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reducer;
exports.startUpdate = startUpdate;
exports.updateSuccess = updateSuccess;
exports.updateError = updateError;

var _modal = require('./modal');

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var OPTION_UPDATE_START = exports.OPTION_UPDATE_START = 'UI_OPTION_UPDATE_START';
var OPTION_UPDATE_SUCCESS = exports.OPTION_UPDATE_SUCCESS = 'UI_OPTION_UPDATE_SUCCESS';
var OPTION_UPDATE_ERROR = exports.OPTION_UPDATE_ERROR = 'UI_OPTION_UPDATE_ERROR';

var defaultState = {
    /* optionName -> {isUpdating, value (client-side), error} */
};

function reducer() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];

    switch (action.type) {
        case OPTION_UPDATE_START:
            return _extends({}, state, _defineProperty({}, action.option, {
                isUpdating: true,
                value: action.value,
                error: false
            }));

        case OPTION_UPDATE_SUCCESS:
            return _extends({}, state, _defineProperty({}, action.option, undefined));

        case OPTION_UPDATE_ERROR:
            var val = state[action.option].value;
            if (typeof val === "boolean") {
                // If a boolean option errs, reset it to its previous state to be less confusing.
                // Example: Start mitmweb, check "add_upstream_certs_to_client_chain".
                val = !val;
            }
            return _extends({}, state, _defineProperty({}, action.option, {
                value: val,
                isUpdating: false,
                error: action.error
            }));

        case _modal.HIDE_MODAL:
            return {};

        default:
            return state;
    }
}

function startUpdate(option, value) {
    return {
        type: OPTION_UPDATE_START,
        option: option,
        value: value
    };
}
function updateSuccess(option) {
    return {
        type: OPTION_UPDATE_SUCCESS,
        option: option
    };
}

function updateError(option, error) {
    return {
        type: OPTION_UPDATE_ERROR,
        option: option,
        error: error
    };
}

},{"./modal":65}],67:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.RECEIVE = exports.REMOVE = exports.UPDATE = exports.ADD = exports.SET_SORT = exports.SET_FILTER = undefined;

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.default = reduce;
exports.setFilter = setFilter;
exports.setSort = setSort;
exports.add = add;
exports.update = update;
exports.remove = remove;
exports.receive = receive;

var _stable = require('stable');

var _stable2 = _interopRequireDefault(_stable);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

var SET_FILTER = exports.SET_FILTER = 'LIST_SET_FILTER';
var SET_SORT = exports.SET_SORT = 'LIST_SET_SORT';
var ADD = exports.ADD = 'LIST_ADD';
var UPDATE = exports.UPDATE = 'LIST_UPDATE';
var REMOVE = exports.REMOVE = 'LIST_REMOVE';
var RECEIVE = exports.RECEIVE = 'LIST_RECEIVE';

var defaultState = {
    byId: {},
    list: [],
    listIndex: {},
    view: [],
    viewIndex: {}

    /**
     * The store reducer can be used as a mixin to another reducer that always returns a
     * new { byId, list, listIndex, view, viewIndex } object. The reducer using the store
     * usually has to map its action to the matching store action and then call the mixin with that.
     *
     * Example Usage:
     *
     *      import reduceStore, * as storeActions from "./utils/store"
     *
     *      case EVENTLOG_ADD:
     *          return {
     *              ...state,
     *              ...reduceStore(state, storeActions.add(action.data))
     *          }
     *
     */
};function reduce() {
    var state = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultState;
    var action = arguments[1];
    var byId = state.byId,
        list = state.list,
        listIndex = state.listIndex,
        view = state.view,
        viewIndex = state.viewIndex;


    switch (action.type) {
        case SET_FILTER:
            view = (0, _stable2.default)(list.filter(action.filter), action.sort);
            viewIndex = {};
            view.forEach(function (item, index) {
                viewIndex[item.id] = index;
            });
            break;

        case SET_SORT:
            view = (0, _stable2.default)([].concat(_toConsumableArray(view)), action.sort);
            viewIndex = {};
            view.forEach(function (item, index) {
                viewIndex[item.id] = index;
            });
            break;

        case ADD:
            if (action.item.id in byId) {
                // we already had that.
                break;
            }
            byId = _extends({}, byId, _defineProperty({}, action.item.id, action.item));
            listIndex = _extends({}, listIndex, _defineProperty({}, action.item.id, list.length));
            list = [].concat(_toConsumableArray(list), [action.item]);
            if (action.filter(action.item)) {
                var _sortedInsert = sortedInsert(state, action.item, action.sort);

                view = _sortedInsert.view;
                viewIndex = _sortedInsert.viewIndex;
            }
            break;

        case UPDATE:
            byId = _extends({}, byId, _defineProperty({}, action.item.id, action.item));
            list = [].concat(_toConsumableArray(list));
            list[listIndex[action.item.id]] = action.item;

            var hasOldItem = action.item.id in viewIndex;
            var hasNewItem = action.filter(action.item);
            if (hasNewItem && !hasOldItem) {
                var _sortedInsert2 = sortedInsert(state, action.item, action.sort);

                view = _sortedInsert2.view;
                viewIndex = _sortedInsert2.viewIndex;
            } else if (!hasNewItem && hasOldItem) {
                var _removeData = removeData(view, viewIndex, action.item.id);

                view = _removeData.data;
                viewIndex = _removeData.dataIndex;
            } else if (hasNewItem && hasOldItem) {
                var _sortedUpdate = sortedUpdate(state, action.item, action.sort);

                view = _sortedUpdate.view;
                viewIndex = _sortedUpdate.viewIndex;
            }
            break;

        case REMOVE:
            if (!(action.id in byId)) {
                break;
            }
            byId = _extends({}, byId);
            delete byId[action.id];

            var _removeData2 = removeData(list, listIndex, action.id);

            list = _removeData2.data;
            listIndex = _removeData2.dataIndex;


            if (action.id in viewIndex) {
                var _removeData3 = removeData(view, viewIndex, action.id);

                view = _removeData3.data;
                viewIndex = _removeData3.dataIndex;
            }
            break;

        case RECEIVE:
            list = action.list;
            listIndex = {};
            byId = {};
            list.forEach(function (item, i) {
                byId[item.id] = item;
                listIndex[item.id] = i;
            });
            view = list.filter(action.filter).sort(action.sort);
            viewIndex = {};
            view.forEach(function (item, index) {
                viewIndex[item.id] = index;
            });
            break;
    }
    return { byId: byId, list: list, listIndex: listIndex, view: view, viewIndex: viewIndex };
}

function setFilter() {
    var filter = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultFilter;
    var sort = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : defaultSort;

    return { type: SET_FILTER, filter: filter, sort: sort };
}

function setSort() {
    var sort = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : defaultSort;

    return { type: SET_SORT, sort: sort };
}

function add(item) {
    var filter = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : defaultFilter;
    var sort = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : defaultSort;

    return { type: ADD, item: item, filter: filter, sort: sort };
}

function update(item) {
    var filter = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : defaultFilter;
    var sort = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : defaultSort;

    return { type: UPDATE, item: item, filter: filter, sort: sort };
}

function remove(id) {
    return { type: REMOVE, id: id };
}

function receive(list) {
    var filter = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : defaultFilter;
    var sort = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : defaultSort;

    return { type: RECEIVE, list: list, filter: filter, sort: sort };
}

function sortedInsert(state, item, sort) {
    var index = sortedIndex(state.view, item, sort);
    var view = [].concat(_toConsumableArray(state.view));
    var viewIndex = _extends({}, state.viewIndex);

    view.splice(index, 0, item);
    for (var i = view.length - 1; i >= index; i--) {
        viewIndex[view[i].id] = i;
    }

    return { view: view, viewIndex: viewIndex };
}

function removeData(currentData, currentDataIndex, id) {
    var index = currentDataIndex[id];
    var data = [].concat(_toConsumableArray(currentData));
    var dataIndex = _extends({}, currentDataIndex);
    delete dataIndex[id];

    data.splice(index, 1);
    for (var i = data.length - 1; i >= index; i--) {
        dataIndex[data[i].id] = i;
    }

    return { data: data, dataIndex: dataIndex };
}

function sortedUpdate(state, item, sort) {
    var view = [].concat(_toConsumableArray(state.view));
    var viewIndex = _extends({}, state.viewIndex);
    var index = viewIndex[item.id];
    view[index] = item;
    while (index + 1 < view.length && sort(view[index], view[index + 1]) > 0) {
        view[index] = view[index + 1];
        view[index + 1] = item;
        viewIndex[item.id] = index + 1;
        viewIndex[view[index].id] = index;
        ++index;
    }
    while (index > 0 && sort(view[index], view[index - 1]) < 0) {
        view[index] = view[index - 1];
        view[index - 1] = item;
        viewIndex[item.id] = index - 1;
        viewIndex[view[index].id] = index;
        --index;
    }
    return { view: view, viewIndex: viewIndex };
}

function sortedIndex(list, item, sort) {
    var low = 0;
    var high = list.length;

    while (low < high) {
        var middle = low + high >>> 1;
        if (sort(item, list[middle]) >= 0) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    return low;
}

function defaultFilter() {
    return true;
}

function defaultSort(a, b) {
    return 0;
}

},{"stable":"stable"}],68:[function(require,module,exports){
"use strict";

module.exports = function () {
  "use strict";

  /*
   * Generated by PEG.js 0.9.0.
   *
   * http://pegjs.org/
   */

  function peg$subclass(child, parent) {
    function ctor() {
      this.constructor = child;
    }
    ctor.prototype = parent.prototype;
    child.prototype = new ctor();
  }

  function peg$SyntaxError(message, expected, found, location) {
    this.message = message;
    this.expected = expected;
    this.found = found;
    this.location = location;
    this.name = "SyntaxError";

    if (typeof Error.captureStackTrace === "function") {
      Error.captureStackTrace(this, peg$SyntaxError);
    }
  }

  peg$subclass(peg$SyntaxError, Error);

  function peg$parse(input) {
    var options = arguments.length > 1 ? arguments[1] : {},
        parser = this,
        peg$FAILED = {},
        peg$startRuleFunctions = { start: peg$parsestart },
        peg$startRuleFunction = peg$parsestart,
        peg$c0 = { type: "other", description: "filter expression" },
        peg$c1 = function peg$c1(orExpr) {
      return orExpr;
    },
        peg$c2 = { type: "other", description: "whitespace" },
        peg$c3 = /^[ \t\n\r]/,
        peg$c4 = { type: "class", value: "[ \\t\\n\\r]", description: "[ \\t\\n\\r]" },
        peg$c5 = { type: "other", description: "control character" },
        peg$c6 = /^[|&!()~"]/,
        peg$c7 = { type: "class", value: "[|&!()~\"]", description: "[|&!()~\"]" },
        peg$c8 = { type: "other", description: "optional whitespace" },
        peg$c9 = "|",
        peg$c10 = { type: "literal", value: "|", description: "\"|\"" },
        peg$c11 = function peg$c11(first, second) {
      return or(first, second);
    },
        peg$c12 = "&",
        peg$c13 = { type: "literal", value: "&", description: "\"&\"" },
        peg$c14 = function peg$c14(first, second) {
      return and(first, second);
    },
        peg$c15 = "!",
        peg$c16 = { type: "literal", value: "!", description: "\"!\"" },
        peg$c17 = function peg$c17(expr) {
      return not(expr);
    },
        peg$c18 = "(",
        peg$c19 = { type: "literal", value: "(", description: "\"(\"" },
        peg$c20 = ")",
        peg$c21 = { type: "literal", value: ")", description: "\")\"" },
        peg$c22 = function peg$c22(expr) {
      return binding(expr);
    },
        peg$c23 = "true",
        peg$c24 = { type: "literal", value: "true", description: "\"true\"" },
        peg$c25 = function peg$c25() {
      return trueFilter;
    },
        peg$c26 = "false",
        peg$c27 = { type: "literal", value: "false", description: "\"false\"" },
        peg$c28 = function peg$c28() {
      return falseFilter;
    },
        peg$c29 = "~a",
        peg$c30 = { type: "literal", value: "~a", description: "\"~a\"" },
        peg$c31 = function peg$c31() {
      return assetFilter;
    },
        peg$c32 = "~b",
        peg$c33 = { type: "literal", value: "~b", description: "\"~b\"" },
        peg$c34 = function peg$c34(s) {
      return body(s);
    },
        peg$c35 = "~bq",
        peg$c36 = { type: "literal", value: "~bq", description: "\"~bq\"" },
        peg$c37 = function peg$c37(s) {
      return requestBody(s);
    },
        peg$c38 = "~bs",
        peg$c39 = { type: "literal", value: "~bs", description: "\"~bs\"" },
        peg$c40 = function peg$c40(s) {
      return responseBody(s);
    },
        peg$c41 = "~c",
        peg$c42 = { type: "literal", value: "~c", description: "\"~c\"" },
        peg$c43 = function peg$c43(s) {
      return responseCode(s);
    },
        peg$c44 = "~d",
        peg$c45 = { type: "literal", value: "~d", description: "\"~d\"" },
        peg$c46 = function peg$c46(s) {
      return domain(s);
    },
        peg$c47 = "~dst",
        peg$c48 = { type: "literal", value: "~dst", description: "\"~dst\"" },
        peg$c49 = function peg$c49(s) {
      return destination(s);
    },
        peg$c50 = "~e",
        peg$c51 = { type: "literal", value: "~e", description: "\"~e\"" },
        peg$c52 = function peg$c52() {
      return errorFilter;
    },
        peg$c53 = "~h",
        peg$c54 = { type: "literal", value: "~h", description: "\"~h\"" },
        peg$c55 = function peg$c55(s) {
      return header(s);
    },
        peg$c56 = "~hq",
        peg$c57 = { type: "literal", value: "~hq", description: "\"~hq\"" },
        peg$c58 = function peg$c58(s) {
      return requestHeader(s);
    },
        peg$c59 = "~hs",
        peg$c60 = { type: "literal", value: "~hs", description: "\"~hs\"" },
        peg$c61 = function peg$c61(s) {
      return responseHeader(s);
    },
        peg$c62 = "~http",
        peg$c63 = { type: "literal", value: "~http", description: "\"~http\"" },
        peg$c64 = function peg$c64() {
      return httpFilter;
    },
        peg$c65 = "~m",
        peg$c66 = { type: "literal", value: "~m", description: "\"~m\"" },
        peg$c67 = function peg$c67(s) {
      return method(s);
    },
        peg$c68 = "~marked",
        peg$c69 = { type: "literal", value: "~marked", description: "\"~marked\"" },
        peg$c70 = function peg$c70() {
      return markedFilter;
    },
        peg$c71 = "~q",
        peg$c72 = { type: "literal", value: "~q", description: "\"~q\"" },
        peg$c73 = function peg$c73() {
      return noResponseFilter;
    },
        peg$c74 = "~src",
        peg$c75 = { type: "literal", value: "~src", description: "\"~src\"" },
        peg$c76 = function peg$c76(s) {
      return source(s);
    },
        peg$c77 = "~s",
        peg$c78 = { type: "literal", value: "~s", description: "\"~s\"" },
        peg$c79 = function peg$c79() {
      return responseFilter;
    },
        peg$c80 = "~t",
        peg$c81 = { type: "literal", value: "~t", description: "\"~t\"" },
        peg$c82 = function peg$c82(s) {
      return contentType(s);
    },
        peg$c83 = "~tcp",
        peg$c84 = { type: "literal", value: "~tcp", description: "\"~tcp\"" },
        peg$c85 = function peg$c85() {
      return tcpFilter;
    },
        peg$c86 = "~tq",
        peg$c87 = { type: "literal", value: "~tq", description: "\"~tq\"" },
        peg$c88 = function peg$c88(s) {
      return requestContentType(s);
    },
        peg$c89 = "~ts",
        peg$c90 = { type: "literal", value: "~ts", description: "\"~ts\"" },
        peg$c91 = function peg$c91(s) {
      return responseContentType(s);
    },
        peg$c92 = "~u",
        peg$c93 = { type: "literal", value: "~u", description: "\"~u\"" },
        peg$c94 = function peg$c94(s) {
      return url(s);
    },
        peg$c95 = "~websocket",
        peg$c96 = { type: "literal", value: "~websocket", description: "\"~websocket\"" },
        peg$c97 = function peg$c97() {
      return websocketFilter;
    },
        peg$c98 = { type: "other", description: "integer" },
        peg$c99 = /^['"]/,
        peg$c100 = { type: "class", value: "['\"]", description: "['\"]" },
        peg$c101 = /^[0-9]/,
        peg$c102 = { type: "class", value: "[0-9]", description: "[0-9]" },
        peg$c103 = function peg$c103(digits) {
      return parseInt(digits.join(""), 10);
    },
        peg$c104 = { type: "other", description: "string" },
        peg$c105 = "\"",
        peg$c106 = { type: "literal", value: "\"", description: "\"\\\"\"" },
        peg$c107 = function peg$c107(chars) {
      return chars.join("");
    },
        peg$c108 = "'",
        peg$c109 = { type: "literal", value: "'", description: "\"'\"" },
        peg$c110 = /^["\\]/,
        peg$c111 = { type: "class", value: "[\"\\\\]", description: "[\"\\\\]" },
        peg$c112 = { type: "any", description: "any character" },
        peg$c113 = function peg$c113(char) {
      return char;
    },
        peg$c114 = "\\",
        peg$c115 = { type: "literal", value: "\\", description: "\"\\\\\"" },
        peg$c116 = /^['\\]/,
        peg$c117 = { type: "class", value: "['\\\\]", description: "['\\\\]" },
        peg$c118 = /^['"\\]/,
        peg$c119 = { type: "class", value: "['\"\\\\]", description: "['\"\\\\]" },
        peg$c120 = "n",
        peg$c121 = { type: "literal", value: "n", description: "\"n\"" },
        peg$c122 = function peg$c122() {
      return "\n";
    },
        peg$c123 = "r",
        peg$c124 = { type: "literal", value: "r", description: "\"r\"" },
        peg$c125 = function peg$c125() {
      return "\r";
    },
        peg$c126 = "t",
        peg$c127 = { type: "literal", value: "t", description: "\"t\"" },
        peg$c128 = function peg$c128() {
      return "\t";
    },
        peg$currPos = 0,
        peg$savedPos = 0,
        peg$posDetailsCache = [{ line: 1, column: 1, seenCR: false }],
        peg$maxFailPos = 0,
        peg$maxFailExpected = [],
        peg$silentFails = 0,
        peg$result;

    if ("startRule" in options) {
      if (!(options.startRule in peg$startRuleFunctions)) {
        throw new Error("Can't start parsing from rule \"" + options.startRule + "\".");
      }

      peg$startRuleFunction = peg$startRuleFunctions[options.startRule];
    }

    function text() {
      return input.substring(peg$savedPos, peg$currPos);
    }

    function location() {
      return peg$computeLocation(peg$savedPos, peg$currPos);
    }

    function expected(description) {
      throw peg$buildException(null, [{ type: "other", description: description }], input.substring(peg$savedPos, peg$currPos), peg$computeLocation(peg$savedPos, peg$currPos));
    }

    function error(message) {
      throw peg$buildException(message, null, input.substring(peg$savedPos, peg$currPos), peg$computeLocation(peg$savedPos, peg$currPos));
    }

    function peg$computePosDetails(pos) {
      var details = peg$posDetailsCache[pos],
          p,
          ch;

      if (details) {
        return details;
      } else {
        p = pos - 1;
        while (!peg$posDetailsCache[p]) {
          p--;
        }

        details = peg$posDetailsCache[p];
        details = {
          line: details.line,
          column: details.column,
          seenCR: details.seenCR
        };

        while (p < pos) {
          ch = input.charAt(p);
          if (ch === "\n") {
            if (!details.seenCR) {
              details.line++;
            }
            details.column = 1;
            details.seenCR = false;
          } else if (ch === "\r" || ch === "\u2028" || ch === "\u2029") {
            details.line++;
            details.column = 1;
            details.seenCR = true;
          } else {
            details.column++;
            details.seenCR = false;
          }

          p++;
        }

        peg$posDetailsCache[pos] = details;
        return details;
      }
    }

    function peg$computeLocation(startPos, endPos) {
      var startPosDetails = peg$computePosDetails(startPos),
          endPosDetails = peg$computePosDetails(endPos);

      return {
        start: {
          offset: startPos,
          line: startPosDetails.line,
          column: startPosDetails.column
        },
        end: {
          offset: endPos,
          line: endPosDetails.line,
          column: endPosDetails.column
        }
      };
    }

    function peg$fail(expected) {
      if (peg$currPos < peg$maxFailPos) {
        return;
      }

      if (peg$currPos > peg$maxFailPos) {
        peg$maxFailPos = peg$currPos;
        peg$maxFailExpected = [];
      }

      peg$maxFailExpected.push(expected);
    }

    function peg$buildException(message, expected, found, location) {
      function cleanupExpected(expected) {
        var i = 1;

        expected.sort(function (a, b) {
          if (a.description < b.description) {
            return -1;
          } else if (a.description > b.description) {
            return 1;
          } else {
            return 0;
          }
        });

        while (i < expected.length) {
          if (expected[i - 1] === expected[i]) {
            expected.splice(i, 1);
          } else {
            i++;
          }
        }
      }

      function buildMessage(expected, found) {
        function stringEscape(s) {
          function hex(ch) {
            return ch.charCodeAt(0).toString(16).toUpperCase();
          }

          return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\x08/g, '\\b').replace(/\t/g, '\\t').replace(/\n/g, '\\n').replace(/\f/g, '\\f').replace(/\r/g, '\\r').replace(/[\x00-\x07\x0B\x0E\x0F]/g, function (ch) {
            return '\\x0' + hex(ch);
          }).replace(/[\x10-\x1F\x80-\xFF]/g, function (ch) {
            return '\\x' + hex(ch);
          }).replace(/[\u0100-\u0FFF]/g, function (ch) {
            return "\\u0" + hex(ch);
          }).replace(/[\u1000-\uFFFF]/g, function (ch) {
            return "\\u" + hex(ch);
          });
        }

        var expectedDescs = new Array(expected.length),
            expectedDesc,
            foundDesc,
            i;

        for (i = 0; i < expected.length; i++) {
          expectedDescs[i] = expected[i].description;
        }

        expectedDesc = expected.length > 1 ? expectedDescs.slice(0, -1).join(", ") + " or " + expectedDescs[expected.length - 1] : expectedDescs[0];

        foundDesc = found ? "\"" + stringEscape(found) + "\"" : "end of input";

        return "Expected " + expectedDesc + " but " + foundDesc + " found.";
      }

      if (expected !== null) {
        cleanupExpected(expected);
      }

      return new peg$SyntaxError(message !== null ? message : buildMessage(expected, found), expected, found, location);
    }

    function peg$parsestart() {
      var s0, s1, s2, s3;

      peg$silentFails++;
      s0 = peg$currPos;
      s1 = peg$parse__();
      if (s1 !== peg$FAILED) {
        s2 = peg$parseOrExpr();
        if (s2 !== peg$FAILED) {
          s3 = peg$parse__();
          if (s3 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c1(s2);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c0);
        }
      }

      return s0;
    }

    function peg$parsews() {
      var s0, s1;

      peg$silentFails++;
      if (peg$c3.test(input.charAt(peg$currPos))) {
        s0 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s0 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c4);
        }
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c2);
        }
      }

      return s0;
    }

    function peg$parsecc() {
      var s0, s1;

      peg$silentFails++;
      if (peg$c6.test(input.charAt(peg$currPos))) {
        s0 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s0 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c7);
        }
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c5);
        }
      }

      return s0;
    }

    function peg$parse__() {
      var s0, s1;

      peg$silentFails++;
      s0 = [];
      s1 = peg$parsews();
      while (s1 !== peg$FAILED) {
        s0.push(s1);
        s1 = peg$parsews();
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c8);
        }
      }

      return s0;
    }

    function peg$parseOrExpr() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$parseAndExpr();
      if (s1 !== peg$FAILED) {
        s2 = peg$parse__();
        if (s2 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 124) {
            s3 = peg$c9;
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c10);
            }
          }
          if (s3 !== peg$FAILED) {
            s4 = peg$parse__();
            if (s4 !== peg$FAILED) {
              s5 = peg$parseOrExpr();
              if (s5 !== peg$FAILED) {
                peg$savedPos = s0;
                s1 = peg$c11(s1, s5);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$FAILED;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$parseAndExpr();
      }

      return s0;
    }

    function peg$parseAndExpr() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      s1 = peg$parseNotExpr();
      if (s1 !== peg$FAILED) {
        s2 = peg$parse__();
        if (s2 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 38) {
            s3 = peg$c12;
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c13);
            }
          }
          if (s3 !== peg$FAILED) {
            s4 = peg$parse__();
            if (s4 !== peg$FAILED) {
              s5 = peg$parseAndExpr();
              if (s5 !== peg$FAILED) {
                peg$savedPos = s0;
                s1 = peg$c14(s1, s5);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$FAILED;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        s1 = peg$parseNotExpr();
        if (s1 !== peg$FAILED) {
          s2 = [];
          s3 = peg$parsews();
          if (s3 !== peg$FAILED) {
            while (s3 !== peg$FAILED) {
              s2.push(s3);
              s3 = peg$parsews();
            }
          } else {
            s2 = peg$FAILED;
          }
          if (s2 !== peg$FAILED) {
            s3 = peg$parseAndExpr();
            if (s3 !== peg$FAILED) {
              peg$savedPos = s0;
              s1 = peg$c14(s1, s3);
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
        if (s0 === peg$FAILED) {
          s0 = peg$parseNotExpr();
        }
      }

      return s0;
    }

    function peg$parseNotExpr() {
      var s0, s1, s2, s3;

      s0 = peg$currPos;
      if (input.charCodeAt(peg$currPos) === 33) {
        s1 = peg$c15;
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c16);
        }
      }
      if (s1 !== peg$FAILED) {
        s2 = peg$parse__();
        if (s2 !== peg$FAILED) {
          s3 = peg$parseNotExpr();
          if (s3 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c17(s3);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$parseBindingExpr();
      }

      return s0;
    }

    function peg$parseBindingExpr() {
      var s0, s1, s2, s3, s4, s5;

      s0 = peg$currPos;
      if (input.charCodeAt(peg$currPos) === 40) {
        s1 = peg$c18;
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c19);
        }
      }
      if (s1 !== peg$FAILED) {
        s2 = peg$parse__();
        if (s2 !== peg$FAILED) {
          s3 = peg$parseOrExpr();
          if (s3 !== peg$FAILED) {
            s4 = peg$parse__();
            if (s4 !== peg$FAILED) {
              if (input.charCodeAt(peg$currPos) === 41) {
                s5 = peg$c20;
                peg$currPos++;
              } else {
                s5 = peg$FAILED;
                if (peg$silentFails === 0) {
                  peg$fail(peg$c21);
                }
              }
              if (s5 !== peg$FAILED) {
                peg$savedPos = s0;
                s1 = peg$c22(s3);
                s0 = s1;
              } else {
                peg$currPos = s0;
                s0 = peg$FAILED;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$parseExpr();
      }

      return s0;
    }

    function peg$parseExpr() {
      var s0, s1, s2, s3;

      s0 = peg$currPos;
      if (input.substr(peg$currPos, 4) === peg$c23) {
        s1 = peg$c23;
        peg$currPos += 4;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c24);
        }
      }
      if (s1 !== peg$FAILED) {
        peg$savedPos = s0;
        s1 = peg$c25();
      }
      s0 = s1;
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.substr(peg$currPos, 5) === peg$c26) {
          s1 = peg$c26;
          peg$currPos += 5;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c27);
          }
        }
        if (s1 !== peg$FAILED) {
          peg$savedPos = s0;
          s1 = peg$c28();
        }
        s0 = s1;
        if (s0 === peg$FAILED) {
          s0 = peg$currPos;
          if (input.substr(peg$currPos, 2) === peg$c29) {
            s1 = peg$c29;
            peg$currPos += 2;
          } else {
            s1 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c30);
            }
          }
          if (s1 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c31();
          }
          s0 = s1;
          if (s0 === peg$FAILED) {
            s0 = peg$currPos;
            if (input.substr(peg$currPos, 2) === peg$c32) {
              s1 = peg$c32;
              peg$currPos += 2;
            } else {
              s1 = peg$FAILED;
              if (peg$silentFails === 0) {
                peg$fail(peg$c33);
              }
            }
            if (s1 !== peg$FAILED) {
              s2 = [];
              s3 = peg$parsews();
              if (s3 !== peg$FAILED) {
                while (s3 !== peg$FAILED) {
                  s2.push(s3);
                  s3 = peg$parsews();
                }
              } else {
                s2 = peg$FAILED;
              }
              if (s2 !== peg$FAILED) {
                s3 = peg$parseStringLiteral();
                if (s3 !== peg$FAILED) {
                  peg$savedPos = s0;
                  s1 = peg$c34(s3);
                  s0 = s1;
                } else {
                  peg$currPos = s0;
                  s0 = peg$FAILED;
                }
              } else {
                peg$currPos = s0;
                s0 = peg$FAILED;
              }
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
            if (s0 === peg$FAILED) {
              s0 = peg$currPos;
              if (input.substr(peg$currPos, 3) === peg$c35) {
                s1 = peg$c35;
                peg$currPos += 3;
              } else {
                s1 = peg$FAILED;
                if (peg$silentFails === 0) {
                  peg$fail(peg$c36);
                }
              }
              if (s1 !== peg$FAILED) {
                s2 = [];
                s3 = peg$parsews();
                if (s3 !== peg$FAILED) {
                  while (s3 !== peg$FAILED) {
                    s2.push(s3);
                    s3 = peg$parsews();
                  }
                } else {
                  s2 = peg$FAILED;
                }
                if (s2 !== peg$FAILED) {
                  s3 = peg$parseStringLiteral();
                  if (s3 !== peg$FAILED) {
                    peg$savedPos = s0;
                    s1 = peg$c37(s3);
                    s0 = s1;
                  } else {
                    peg$currPos = s0;
                    s0 = peg$FAILED;
                  }
                } else {
                  peg$currPos = s0;
                  s0 = peg$FAILED;
                }
              } else {
                peg$currPos = s0;
                s0 = peg$FAILED;
              }
              if (s0 === peg$FAILED) {
                s0 = peg$currPos;
                if (input.substr(peg$currPos, 3) === peg$c38) {
                  s1 = peg$c38;
                  peg$currPos += 3;
                } else {
                  s1 = peg$FAILED;
                  if (peg$silentFails === 0) {
                    peg$fail(peg$c39);
                  }
                }
                if (s1 !== peg$FAILED) {
                  s2 = [];
                  s3 = peg$parsews();
                  if (s3 !== peg$FAILED) {
                    while (s3 !== peg$FAILED) {
                      s2.push(s3);
                      s3 = peg$parsews();
                    }
                  } else {
                    s2 = peg$FAILED;
                  }
                  if (s2 !== peg$FAILED) {
                    s3 = peg$parseStringLiteral();
                    if (s3 !== peg$FAILED) {
                      peg$savedPos = s0;
                      s1 = peg$c40(s3);
                      s0 = s1;
                    } else {
                      peg$currPos = s0;
                      s0 = peg$FAILED;
                    }
                  } else {
                    peg$currPos = s0;
                    s0 = peg$FAILED;
                  }
                } else {
                  peg$currPos = s0;
                  s0 = peg$FAILED;
                }
                if (s0 === peg$FAILED) {
                  s0 = peg$currPos;
                  if (input.substr(peg$currPos, 2) === peg$c41) {
                    s1 = peg$c41;
                    peg$currPos += 2;
                  } else {
                    s1 = peg$FAILED;
                    if (peg$silentFails === 0) {
                      peg$fail(peg$c42);
                    }
                  }
                  if (s1 !== peg$FAILED) {
                    s2 = [];
                    s3 = peg$parsews();
                    if (s3 !== peg$FAILED) {
                      while (s3 !== peg$FAILED) {
                        s2.push(s3);
                        s3 = peg$parsews();
                      }
                    } else {
                      s2 = peg$FAILED;
                    }
                    if (s2 !== peg$FAILED) {
                      s3 = peg$parseIntegerLiteral();
                      if (s3 !== peg$FAILED) {
                        peg$savedPos = s0;
                        s1 = peg$c43(s3);
                        s0 = s1;
                      } else {
                        peg$currPos = s0;
                        s0 = peg$FAILED;
                      }
                    } else {
                      peg$currPos = s0;
                      s0 = peg$FAILED;
                    }
                  } else {
                    peg$currPos = s0;
                    s0 = peg$FAILED;
                  }
                  if (s0 === peg$FAILED) {
                    s0 = peg$currPos;
                    if (input.substr(peg$currPos, 2) === peg$c44) {
                      s1 = peg$c44;
                      peg$currPos += 2;
                    } else {
                      s1 = peg$FAILED;
                      if (peg$silentFails === 0) {
                        peg$fail(peg$c45);
                      }
                    }
                    if (s1 !== peg$FAILED) {
                      s2 = [];
                      s3 = peg$parsews();
                      if (s3 !== peg$FAILED) {
                        while (s3 !== peg$FAILED) {
                          s2.push(s3);
                          s3 = peg$parsews();
                        }
                      } else {
                        s2 = peg$FAILED;
                      }
                      if (s2 !== peg$FAILED) {
                        s3 = peg$parseStringLiteral();
                        if (s3 !== peg$FAILED) {
                          peg$savedPos = s0;
                          s1 = peg$c46(s3);
                          s0 = s1;
                        } else {
                          peg$currPos = s0;
                          s0 = peg$FAILED;
                        }
                      } else {
                        peg$currPos = s0;
                        s0 = peg$FAILED;
                      }
                    } else {
                      peg$currPos = s0;
                      s0 = peg$FAILED;
                    }
                    if (s0 === peg$FAILED) {
                      s0 = peg$currPos;
                      if (input.substr(peg$currPos, 4) === peg$c47) {
                        s1 = peg$c47;
                        peg$currPos += 4;
                      } else {
                        s1 = peg$FAILED;
                        if (peg$silentFails === 0) {
                          peg$fail(peg$c48);
                        }
                      }
                      if (s1 !== peg$FAILED) {
                        s2 = [];
                        s3 = peg$parsews();
                        if (s3 !== peg$FAILED) {
                          while (s3 !== peg$FAILED) {
                            s2.push(s3);
                            s3 = peg$parsews();
                          }
                        } else {
                          s2 = peg$FAILED;
                        }
                        if (s2 !== peg$FAILED) {
                          s3 = peg$parseStringLiteral();
                          if (s3 !== peg$FAILED) {
                            peg$savedPos = s0;
                            s1 = peg$c49(s3);
                            s0 = s1;
                          } else {
                            peg$currPos = s0;
                            s0 = peg$FAILED;
                          }
                        } else {
                          peg$currPos = s0;
                          s0 = peg$FAILED;
                        }
                      } else {
                        peg$currPos = s0;
                        s0 = peg$FAILED;
                      }
                      if (s0 === peg$FAILED) {
                        s0 = peg$currPos;
                        if (input.substr(peg$currPos, 2) === peg$c50) {
                          s1 = peg$c50;
                          peg$currPos += 2;
                        } else {
                          s1 = peg$FAILED;
                          if (peg$silentFails === 0) {
                            peg$fail(peg$c51);
                          }
                        }
                        if (s1 !== peg$FAILED) {
                          peg$savedPos = s0;
                          s1 = peg$c52();
                        }
                        s0 = s1;
                        if (s0 === peg$FAILED) {
                          s0 = peg$currPos;
                          if (input.substr(peg$currPos, 2) === peg$c53) {
                            s1 = peg$c53;
                            peg$currPos += 2;
                          } else {
                            s1 = peg$FAILED;
                            if (peg$silentFails === 0) {
                              peg$fail(peg$c54);
                            }
                          }
                          if (s1 !== peg$FAILED) {
                            s2 = [];
                            s3 = peg$parsews();
                            if (s3 !== peg$FAILED) {
                              while (s3 !== peg$FAILED) {
                                s2.push(s3);
                                s3 = peg$parsews();
                              }
                            } else {
                              s2 = peg$FAILED;
                            }
                            if (s2 !== peg$FAILED) {
                              s3 = peg$parseStringLiteral();
                              if (s3 !== peg$FAILED) {
                                peg$savedPos = s0;
                                s1 = peg$c55(s3);
                                s0 = s1;
                              } else {
                                peg$currPos = s0;
                                s0 = peg$FAILED;
                              }
                            } else {
                              peg$currPos = s0;
                              s0 = peg$FAILED;
                            }
                          } else {
                            peg$currPos = s0;
                            s0 = peg$FAILED;
                          }
                          if (s0 === peg$FAILED) {
                            s0 = peg$currPos;
                            if (input.substr(peg$currPos, 3) === peg$c56) {
                              s1 = peg$c56;
                              peg$currPos += 3;
                            } else {
                              s1 = peg$FAILED;
                              if (peg$silentFails === 0) {
                                peg$fail(peg$c57);
                              }
                            }
                            if (s1 !== peg$FAILED) {
                              s2 = [];
                              s3 = peg$parsews();
                              if (s3 !== peg$FAILED) {
                                while (s3 !== peg$FAILED) {
                                  s2.push(s3);
                                  s3 = peg$parsews();
                                }
                              } else {
                                s2 = peg$FAILED;
                              }
                              if (s2 !== peg$FAILED) {
                                s3 = peg$parseStringLiteral();
                                if (s3 !== peg$FAILED) {
                                  peg$savedPos = s0;
                                  s1 = peg$c58(s3);
                                  s0 = s1;
                                } else {
                                  peg$currPos = s0;
                                  s0 = peg$FAILED;
                                }
                              } else {
                                peg$currPos = s0;
                                s0 = peg$FAILED;
                              }
                            } else {
                              peg$currPos = s0;
                              s0 = peg$FAILED;
                            }
                            if (s0 === peg$FAILED) {
                              s0 = peg$currPos;
                              if (input.substr(peg$currPos, 3) === peg$c59) {
                                s1 = peg$c59;
                                peg$currPos += 3;
                              } else {
                                s1 = peg$FAILED;
                                if (peg$silentFails === 0) {
                                  peg$fail(peg$c60);
                                }
                              }
                              if (s1 !== peg$FAILED) {
                                s2 = [];
                                s3 = peg$parsews();
                                if (s3 !== peg$FAILED) {
                                  while (s3 !== peg$FAILED) {
                                    s2.push(s3);
                                    s3 = peg$parsews();
                                  }
                                } else {
                                  s2 = peg$FAILED;
                                }
                                if (s2 !== peg$FAILED) {
                                  s3 = peg$parseStringLiteral();
                                  if (s3 !== peg$FAILED) {
                                    peg$savedPos = s0;
                                    s1 = peg$c61(s3);
                                    s0 = s1;
                                  } else {
                                    peg$currPos = s0;
                                    s0 = peg$FAILED;
                                  }
                                } else {
                                  peg$currPos = s0;
                                  s0 = peg$FAILED;
                                }
                              } else {
                                peg$currPos = s0;
                                s0 = peg$FAILED;
                              }
                              if (s0 === peg$FAILED) {
                                s0 = peg$currPos;
                                if (input.substr(peg$currPos, 5) === peg$c62) {
                                  s1 = peg$c62;
                                  peg$currPos += 5;
                                } else {
                                  s1 = peg$FAILED;
                                  if (peg$silentFails === 0) {
                                    peg$fail(peg$c63);
                                  }
                                }
                                if (s1 !== peg$FAILED) {
                                  peg$savedPos = s0;
                                  s1 = peg$c64();
                                }
                                s0 = s1;
                                if (s0 === peg$FAILED) {
                                  s0 = peg$currPos;
                                  if (input.substr(peg$currPos, 2) === peg$c65) {
                                    s1 = peg$c65;
                                    peg$currPos += 2;
                                  } else {
                                    s1 = peg$FAILED;
                                    if (peg$silentFails === 0) {
                                      peg$fail(peg$c66);
                                    }
                                  }
                                  if (s1 !== peg$FAILED) {
                                    s2 = [];
                                    s3 = peg$parsews();
                                    if (s3 !== peg$FAILED) {
                                      while (s3 !== peg$FAILED) {
                                        s2.push(s3);
                                        s3 = peg$parsews();
                                      }
                                    } else {
                                      s2 = peg$FAILED;
                                    }
                                    if (s2 !== peg$FAILED) {
                                      s3 = peg$parseStringLiteral();
                                      if (s3 !== peg$FAILED) {
                                        peg$savedPos = s0;
                                        s1 = peg$c67(s3);
                                        s0 = s1;
                                      } else {
                                        peg$currPos = s0;
                                        s0 = peg$FAILED;
                                      }
                                    } else {
                                      peg$currPos = s0;
                                      s0 = peg$FAILED;
                                    }
                                  } else {
                                    peg$currPos = s0;
                                    s0 = peg$FAILED;
                                  }
                                  if (s0 === peg$FAILED) {
                                    s0 = peg$currPos;
                                    if (input.substr(peg$currPos, 7) === peg$c68) {
                                      s1 = peg$c68;
                                      peg$currPos += 7;
                                    } else {
                                      s1 = peg$FAILED;
                                      if (peg$silentFails === 0) {
                                        peg$fail(peg$c69);
                                      }
                                    }
                                    if (s1 !== peg$FAILED) {
                                      peg$savedPos = s0;
                                      s1 = peg$c70();
                                    }
                                    s0 = s1;
                                    if (s0 === peg$FAILED) {
                                      s0 = peg$currPos;
                                      if (input.substr(peg$currPos, 2) === peg$c71) {
                                        s1 = peg$c71;
                                        peg$currPos += 2;
                                      } else {
                                        s1 = peg$FAILED;
                                        if (peg$silentFails === 0) {
                                          peg$fail(peg$c72);
                                        }
                                      }
                                      if (s1 !== peg$FAILED) {
                                        peg$savedPos = s0;
                                        s1 = peg$c73();
                                      }
                                      s0 = s1;
                                      if (s0 === peg$FAILED) {
                                        s0 = peg$currPos;
                                        if (input.substr(peg$currPos, 4) === peg$c74) {
                                          s1 = peg$c74;
                                          peg$currPos += 4;
                                        } else {
                                          s1 = peg$FAILED;
                                          if (peg$silentFails === 0) {
                                            peg$fail(peg$c75);
                                          }
                                        }
                                        if (s1 !== peg$FAILED) {
                                          s2 = [];
                                          s3 = peg$parsews();
                                          if (s3 !== peg$FAILED) {
                                            while (s3 !== peg$FAILED) {
                                              s2.push(s3);
                                              s3 = peg$parsews();
                                            }
                                          } else {
                                            s2 = peg$FAILED;
                                          }
                                          if (s2 !== peg$FAILED) {
                                            s3 = peg$parseStringLiteral();
                                            if (s3 !== peg$FAILED) {
                                              peg$savedPos = s0;
                                              s1 = peg$c76(s3);
                                              s0 = s1;
                                            } else {
                                              peg$currPos = s0;
                                              s0 = peg$FAILED;
                                            }
                                          } else {
                                            peg$currPos = s0;
                                            s0 = peg$FAILED;
                                          }
                                        } else {
                                          peg$currPos = s0;
                                          s0 = peg$FAILED;
                                        }
                                        if (s0 === peg$FAILED) {
                                          s0 = peg$currPos;
                                          if (input.substr(peg$currPos, 2) === peg$c77) {
                                            s1 = peg$c77;
                                            peg$currPos += 2;
                                          } else {
                                            s1 = peg$FAILED;
                                            if (peg$silentFails === 0) {
                                              peg$fail(peg$c78);
                                            }
                                          }
                                          if (s1 !== peg$FAILED) {
                                            peg$savedPos = s0;
                                            s1 = peg$c79();
                                          }
                                          s0 = s1;
                                          if (s0 === peg$FAILED) {
                                            s0 = peg$currPos;
                                            if (input.substr(peg$currPos, 2) === peg$c80) {
                                              s1 = peg$c80;
                                              peg$currPos += 2;
                                            } else {
                                              s1 = peg$FAILED;
                                              if (peg$silentFails === 0) {
                                                peg$fail(peg$c81);
                                              }
                                            }
                                            if (s1 !== peg$FAILED) {
                                              s2 = [];
                                              s3 = peg$parsews();
                                              if (s3 !== peg$FAILED) {
                                                while (s3 !== peg$FAILED) {
                                                  s2.push(s3);
                                                  s3 = peg$parsews();
                                                }
                                              } else {
                                                s2 = peg$FAILED;
                                              }
                                              if (s2 !== peg$FAILED) {
                                                s3 = peg$parseStringLiteral();
                                                if (s3 !== peg$FAILED) {
                                                  peg$savedPos = s0;
                                                  s1 = peg$c82(s3);
                                                  s0 = s1;
                                                } else {
                                                  peg$currPos = s0;
                                                  s0 = peg$FAILED;
                                                }
                                              } else {
                                                peg$currPos = s0;
                                                s0 = peg$FAILED;
                                              }
                                            } else {
                                              peg$currPos = s0;
                                              s0 = peg$FAILED;
                                            }
                                            if (s0 === peg$FAILED) {
                                              s0 = peg$currPos;
                                              if (input.substr(peg$currPos, 4) === peg$c83) {
                                                s1 = peg$c83;
                                                peg$currPos += 4;
                                              } else {
                                                s1 = peg$FAILED;
                                                if (peg$silentFails === 0) {
                                                  peg$fail(peg$c84);
                                                }
                                              }
                                              if (s1 !== peg$FAILED) {
                                                peg$savedPos = s0;
                                                s1 = peg$c85();
                                              }
                                              s0 = s1;
                                              if (s0 === peg$FAILED) {
                                                s0 = peg$currPos;
                                                if (input.substr(peg$currPos, 3) === peg$c86) {
                                                  s1 = peg$c86;
                                                  peg$currPos += 3;
                                                } else {
                                                  s1 = peg$FAILED;
                                                  if (peg$silentFails === 0) {
                                                    peg$fail(peg$c87);
                                                  }
                                                }
                                                if (s1 !== peg$FAILED) {
                                                  s2 = [];
                                                  s3 = peg$parsews();
                                                  if (s3 !== peg$FAILED) {
                                                    while (s3 !== peg$FAILED) {
                                                      s2.push(s3);
                                                      s3 = peg$parsews();
                                                    }
                                                  } else {
                                                    s2 = peg$FAILED;
                                                  }
                                                  if (s2 !== peg$FAILED) {
                                                    s3 = peg$parseStringLiteral();
                                                    if (s3 !== peg$FAILED) {
                                                      peg$savedPos = s0;
                                                      s1 = peg$c88(s3);
                                                      s0 = s1;
                                                    } else {
                                                      peg$currPos = s0;
                                                      s0 = peg$FAILED;
                                                    }
                                                  } else {
                                                    peg$currPos = s0;
                                                    s0 = peg$FAILED;
                                                  }
                                                } else {
                                                  peg$currPos = s0;
                                                  s0 = peg$FAILED;
                                                }
                                                if (s0 === peg$FAILED) {
                                                  s0 = peg$currPos;
                                                  if (input.substr(peg$currPos, 3) === peg$c89) {
                                                    s1 = peg$c89;
                                                    peg$currPos += 3;
                                                  } else {
                                                    s1 = peg$FAILED;
                                                    if (peg$silentFails === 0) {
                                                      peg$fail(peg$c90);
                                                    }
                                                  }
                                                  if (s1 !== peg$FAILED) {
                                                    s2 = [];
                                                    s3 = peg$parsews();
                                                    if (s3 !== peg$FAILED) {
                                                      while (s3 !== peg$FAILED) {
                                                        s2.push(s3);
                                                        s3 = peg$parsews();
                                                      }
                                                    } else {
                                                      s2 = peg$FAILED;
                                                    }
                                                    if (s2 !== peg$FAILED) {
                                                      s3 = peg$parseStringLiteral();
                                                      if (s3 !== peg$FAILED) {
                                                        peg$savedPos = s0;
                                                        s1 = peg$c91(s3);
                                                        s0 = s1;
                                                      } else {
                                                        peg$currPos = s0;
                                                        s0 = peg$FAILED;
                                                      }
                                                    } else {
                                                      peg$currPos = s0;
                                                      s0 = peg$FAILED;
                                                    }
                                                  } else {
                                                    peg$currPos = s0;
                                                    s0 = peg$FAILED;
                                                  }
                                                  if (s0 === peg$FAILED) {
                                                    s0 = peg$currPos;
                                                    if (input.substr(peg$currPos, 2) === peg$c92) {
                                                      s1 = peg$c92;
                                                      peg$currPos += 2;
                                                    } else {
                                                      s1 = peg$FAILED;
                                                      if (peg$silentFails === 0) {
                                                        peg$fail(peg$c93);
                                                      }
                                                    }
                                                    if (s1 !== peg$FAILED) {
                                                      s2 = [];
                                                      s3 = peg$parsews();
                                                      if (s3 !== peg$FAILED) {
                                                        while (s3 !== peg$FAILED) {
                                                          s2.push(s3);
                                                          s3 = peg$parsews();
                                                        }
                                                      } else {
                                                        s2 = peg$FAILED;
                                                      }
                                                      if (s2 !== peg$FAILED) {
                                                        s3 = peg$parseStringLiteral();
                                                        if (s3 !== peg$FAILED) {
                                                          peg$savedPos = s0;
                                                          s1 = peg$c94(s3);
                                                          s0 = s1;
                                                        } else {
                                                          peg$currPos = s0;
                                                          s0 = peg$FAILED;
                                                        }
                                                      } else {
                                                        peg$currPos = s0;
                                                        s0 = peg$FAILED;
                                                      }
                                                    } else {
                                                      peg$currPos = s0;
                                                      s0 = peg$FAILED;
                                                    }
                                                    if (s0 === peg$FAILED) {
                                                      s0 = peg$currPos;
                                                      if (input.substr(peg$currPos, 10) === peg$c95) {
                                                        s1 = peg$c95;
                                                        peg$currPos += 10;
                                                      } else {
                                                        s1 = peg$FAILED;
                                                        if (peg$silentFails === 0) {
                                                          peg$fail(peg$c96);
                                                        }
                                                      }
                                                      if (s1 !== peg$FAILED) {
                                                        peg$savedPos = s0;
                                                        s1 = peg$c97();
                                                      }
                                                      s0 = s1;
                                                      if (s0 === peg$FAILED) {
                                                        s0 = peg$currPos;
                                                        s1 = peg$parseStringLiteral();
                                                        if (s1 !== peg$FAILED) {
                                                          peg$savedPos = s0;
                                                          s1 = peg$c94(s1);
                                                        }
                                                        s0 = s1;
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      return s0;
    }

    function peg$parseIntegerLiteral() {
      var s0, s1, s2, s3;

      peg$silentFails++;
      s0 = peg$currPos;
      if (peg$c99.test(input.charAt(peg$currPos))) {
        s1 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c100);
        }
      }
      if (s1 === peg$FAILED) {
        s1 = null;
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        if (peg$c101.test(input.charAt(peg$currPos))) {
          s3 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s3 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c102);
          }
        }
        if (s3 !== peg$FAILED) {
          while (s3 !== peg$FAILED) {
            s2.push(s3);
            if (peg$c101.test(input.charAt(peg$currPos))) {
              s3 = input.charAt(peg$currPos);
              peg$currPos++;
            } else {
              s3 = peg$FAILED;
              if (peg$silentFails === 0) {
                peg$fail(peg$c102);
              }
            }
          }
        } else {
          s2 = peg$FAILED;
        }
        if (s2 !== peg$FAILED) {
          if (peg$c99.test(input.charAt(peg$currPos))) {
            s3 = input.charAt(peg$currPos);
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c100);
            }
          }
          if (s3 === peg$FAILED) {
            s3 = null;
          }
          if (s3 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c103(s2);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c98);
        }
      }

      return s0;
    }

    function peg$parseStringLiteral() {
      var s0, s1, s2, s3;

      peg$silentFails++;
      s0 = peg$currPos;
      if (input.charCodeAt(peg$currPos) === 34) {
        s1 = peg$c105;
        peg$currPos++;
      } else {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c106);
        }
      }
      if (s1 !== peg$FAILED) {
        s2 = [];
        s3 = peg$parseDoubleStringChar();
        while (s3 !== peg$FAILED) {
          s2.push(s3);
          s3 = peg$parseDoubleStringChar();
        }
        if (s2 !== peg$FAILED) {
          if (input.charCodeAt(peg$currPos) === 34) {
            s3 = peg$c105;
            peg$currPos++;
          } else {
            s3 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c106);
            }
          }
          if (s3 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c107(s2);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.charCodeAt(peg$currPos) === 39) {
          s1 = peg$c108;
          peg$currPos++;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c109);
          }
        }
        if (s1 !== peg$FAILED) {
          s2 = [];
          s3 = peg$parseSingleStringChar();
          while (s3 !== peg$FAILED) {
            s2.push(s3);
            s3 = peg$parseSingleStringChar();
          }
          if (s2 !== peg$FAILED) {
            if (input.charCodeAt(peg$currPos) === 39) {
              s3 = peg$c108;
              peg$currPos++;
            } else {
              s3 = peg$FAILED;
              if (peg$silentFails === 0) {
                peg$fail(peg$c109);
              }
            }
            if (s3 !== peg$FAILED) {
              peg$savedPos = s0;
              s1 = peg$c107(s2);
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
        if (s0 === peg$FAILED) {
          s0 = peg$currPos;
          s1 = peg$currPos;
          peg$silentFails++;
          s2 = peg$parsecc();
          peg$silentFails--;
          if (s2 === peg$FAILED) {
            s1 = void 0;
          } else {
            peg$currPos = s1;
            s1 = peg$FAILED;
          }
          if (s1 !== peg$FAILED) {
            s2 = [];
            s3 = peg$parseUnquotedStringChar();
            if (s3 !== peg$FAILED) {
              while (s3 !== peg$FAILED) {
                s2.push(s3);
                s3 = peg$parseUnquotedStringChar();
              }
            } else {
              s2 = peg$FAILED;
            }
            if (s2 !== peg$FAILED) {
              peg$savedPos = s0;
              s1 = peg$c107(s2);
              s0 = s1;
            } else {
              peg$currPos = s0;
              s0 = peg$FAILED;
            }
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        }
      }
      peg$silentFails--;
      if (s0 === peg$FAILED) {
        s1 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c104);
        }
      }

      return s0;
    }

    function peg$parseDoubleStringChar() {
      var s0, s1, s2;

      s0 = peg$currPos;
      s1 = peg$currPos;
      peg$silentFails++;
      if (peg$c110.test(input.charAt(peg$currPos))) {
        s2 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s2 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c111);
        }
      }
      peg$silentFails--;
      if (s2 === peg$FAILED) {
        s1 = void 0;
      } else {
        peg$currPos = s1;
        s1 = peg$FAILED;
      }
      if (s1 !== peg$FAILED) {
        if (input.length > peg$currPos) {
          s2 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s2 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c112);
          }
        }
        if (s2 !== peg$FAILED) {
          peg$savedPos = s0;
          s1 = peg$c113(s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.charCodeAt(peg$currPos) === 92) {
          s1 = peg$c114;
          peg$currPos++;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c115);
          }
        }
        if (s1 !== peg$FAILED) {
          s2 = peg$parseEscapeSequence();
          if (s2 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c113(s2);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      }

      return s0;
    }

    function peg$parseSingleStringChar() {
      var s0, s1, s2;

      s0 = peg$currPos;
      s1 = peg$currPos;
      peg$silentFails++;
      if (peg$c116.test(input.charAt(peg$currPos))) {
        s2 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s2 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c117);
        }
      }
      peg$silentFails--;
      if (s2 === peg$FAILED) {
        s1 = void 0;
      } else {
        peg$currPos = s1;
        s1 = peg$FAILED;
      }
      if (s1 !== peg$FAILED) {
        if (input.length > peg$currPos) {
          s2 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s2 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c112);
          }
        }
        if (s2 !== peg$FAILED) {
          peg$savedPos = s0;
          s1 = peg$c113(s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.charCodeAt(peg$currPos) === 92) {
          s1 = peg$c114;
          peg$currPos++;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c115);
          }
        }
        if (s1 !== peg$FAILED) {
          s2 = peg$parseEscapeSequence();
          if (s2 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c113(s2);
            s0 = s1;
          } else {
            peg$currPos = s0;
            s0 = peg$FAILED;
          }
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      }

      return s0;
    }

    function peg$parseUnquotedStringChar() {
      var s0, s1, s2;

      s0 = peg$currPos;
      s1 = peg$currPos;
      peg$silentFails++;
      s2 = peg$parsews();
      peg$silentFails--;
      if (s2 === peg$FAILED) {
        s1 = void 0;
      } else {
        peg$currPos = s1;
        s1 = peg$FAILED;
      }
      if (s1 !== peg$FAILED) {
        if (input.length > peg$currPos) {
          s2 = input.charAt(peg$currPos);
          peg$currPos++;
        } else {
          s2 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c112);
          }
        }
        if (s2 !== peg$FAILED) {
          peg$savedPos = s0;
          s1 = peg$c113(s2);
          s0 = s1;
        } else {
          peg$currPos = s0;
          s0 = peg$FAILED;
        }
      } else {
        peg$currPos = s0;
        s0 = peg$FAILED;
      }

      return s0;
    }

    function peg$parseEscapeSequence() {
      var s0, s1;

      if (peg$c118.test(input.charAt(peg$currPos))) {
        s0 = input.charAt(peg$currPos);
        peg$currPos++;
      } else {
        s0 = peg$FAILED;
        if (peg$silentFails === 0) {
          peg$fail(peg$c119);
        }
      }
      if (s0 === peg$FAILED) {
        s0 = peg$currPos;
        if (input.charCodeAt(peg$currPos) === 110) {
          s1 = peg$c120;
          peg$currPos++;
        } else {
          s1 = peg$FAILED;
          if (peg$silentFails === 0) {
            peg$fail(peg$c121);
          }
        }
        if (s1 !== peg$FAILED) {
          peg$savedPos = s0;
          s1 = peg$c122();
        }
        s0 = s1;
        if (s0 === peg$FAILED) {
          s0 = peg$currPos;
          if (input.charCodeAt(peg$currPos) === 114) {
            s1 = peg$c123;
            peg$currPos++;
          } else {
            s1 = peg$FAILED;
            if (peg$silentFails === 0) {
              peg$fail(peg$c124);
            }
          }
          if (s1 !== peg$FAILED) {
            peg$savedPos = s0;
            s1 = peg$c125();
          }
          s0 = s1;
          if (s0 === peg$FAILED) {
            s0 = peg$currPos;
            if (input.charCodeAt(peg$currPos) === 116) {
              s1 = peg$c126;
              peg$currPos++;
            } else {
              s1 = peg$FAILED;
              if (peg$silentFails === 0) {
                peg$fail(peg$c127);
              }
            }
            if (s1 !== peg$FAILED) {
              peg$savedPos = s0;
              s1 = peg$c128();
            }
            s0 = s1;
          }
        }
      }

      return s0;
    }

    var flowutils = require("../flow/utils.js");

    function or(first, second) {
      // Add explicit function names to ease debugging.
      function orFilter() {
        return first.apply(this, arguments) || second.apply(this, arguments);
      }
      orFilter.desc = first.desc + " or " + second.desc;
      return orFilter;
    }
    function and(first, second) {
      function andFilter() {
        return first.apply(this, arguments) && second.apply(this, arguments);
      }
      andFilter.desc = first.desc + " and " + second.desc;
      return andFilter;
    }
    function not(expr) {
      function notFilter() {
        return !expr.apply(this, arguments);
      }
      notFilter.desc = "not " + expr.desc;
      return notFilter;
    }
    function binding(expr) {
      function bindingFilter() {
        return expr.apply(this, arguments);
      }
      bindingFilter.desc = "(" + expr.desc + ")";
      return bindingFilter;
    }
    function trueFilter(flow) {
      return true;
    }
    trueFilter.desc = "true";
    function falseFilter(flow) {
      return false;
    }
    falseFilter.desc = "false";

    var ASSET_TYPES = [new RegExp("text/javascript"), new RegExp("application/x-javascript"), new RegExp("application/javascript"), new RegExp("text/css"), new RegExp("image/.*"), new RegExp("application/x-shockwave-flash")];
    function assetFilter(flow) {
      if (flow.response) {
        var ct = flowutils.ResponseUtils.getContentType(flow.response);
        var i = ASSET_TYPES.length;
        while (i--) {
          if (ASSET_TYPES[i].test(ct)) {
            return true;
          }
        }
      }
      return false;
    }
    assetFilter.desc = "is asset";
    function responseCode(code) {
      function responseCodeFilter(flow) {
        return flow.response && flow.response.status_code === code;
      }
      responseCodeFilter.desc = "resp. code is " + code;
      return responseCodeFilter;
    }
    function body(regex) {
      regex = new RegExp(regex, "i");
      function bodyFilter(flow) {
        return true;
      }
      bodyFilter.desc = "body filters are not implemented yet, see https://github.com/mitmproxy/mitmweb/issues/10";
      return bodyFilter;
    }
    function requestBody(regex) {
      regex = new RegExp(regex, "i");
      function requestBodyFilter(flow) {
        return true;
      }
      requestBodyFilter.desc = "body filters are not implemented yet, see https://github.com/mitmproxy/mitmweb/issues/10";
      return requestBodyFilter;
    }
    function responseBody(regex) {
      regex = new RegExp(regex, "i");
      function responseBodyFilter(flow) {
        return true;
      }
      responseBodyFilter.desc = "body filters are not implemented yet, see https://github.com/mitmproxy/mitmweb/issues/10";
      return responseBodyFilter;
    }
    function domain(regex) {
      regex = new RegExp(regex, "i");
      function domainFilter(flow) {
        return flow.request && (regex.test(flow.request.host) || regex.test(flow.request.pretty_host));
      }
      domainFilter.desc = "domain matches " + regex;
      return domainFilter;
    }
    function destination(regex) {
      regex = new RegExp(regex, "i");
      function destinationFilter(flow) {
        return !!flow.server_conn.address && regex.test(flow.server_conn.address[0] + ":" + flow.server_conn.address[1]);
      }
      destinationFilter.desc = "destination address matches " + regex;
      return destinationFilter;
    }
    function errorFilter(flow) {
      return !!flow.error;
    }
    errorFilter.desc = "has error";
    function header(regex) {
      regex = new RegExp(regex, "i");
      function headerFilter(flow) {
        return flow.request && flowutils.RequestUtils.match_header(flow.request, regex) || flow.response && flowutils.ResponseUtils.match_header(flow.response, regex);
      }
      headerFilter.desc = "header matches " + regex;
      return headerFilter;
    }
    function requestHeader(regex) {
      regex = new RegExp(regex, "i");
      function requestHeaderFilter(flow) {
        return flow.request && flowutils.RequestUtils.match_header(flow.request, regex);
      }
      requestHeaderFilter.desc = "req. header matches " + regex;
      return requestHeaderFilter;
    }
    function responseHeader(regex) {
      regex = new RegExp(regex, "i");
      function responseHeaderFilter(flow) {
        return flow.response && flowutils.ResponseUtils.match_header(flow.response, regex);
      }
      responseHeaderFilter.desc = "resp. header matches " + regex;
      return responseHeaderFilter;
    }
    function httpFilter(flow) {
      return flow.type === "http";
    }
    httpFilter.desc = "is an HTTP Flow";
    function method(regex) {
      regex = new RegExp(regex, "i");
      function methodFilter(flow) {
        return flow.request && regex.test(flow.request.method);
      }
      methodFilter.desc = "method matches " + regex;
      return methodFilter;
    }
    function markedFilter(flow) {
      return flow.marked;
    }
    markedFilter.desc = "is marked";
    function noResponseFilter(flow) {
      return flow.request && !flow.response;
    }
    noResponseFilter.desc = "has no response";
    function responseFilter(flow) {
      return !!flow.response;
    }
    responseFilter.desc = "has response";
    function source(regex) {
      regex = new RegExp(regex, "i");
      function sourceFilter(flow) {
        return !!flow.client_conn.address && regex.test(flow.client_conn.address[0] + ":" + flow.client_conn.address[1]);
      }
      sourceFilter.desc = "source address matches " + regex;
      return sourceFilter;
    }
    function contentType(regex) {
      regex = new RegExp(regex, "i");
      function contentTypeFilter(flow) {
        return flow.request && regex.test(flowutils.RequestUtils.getContentType(flow.request)) || flow.response && regex.test(flowutils.ResponseUtils.getContentType(flow.response));
      }
      contentTypeFilter.desc = "content type matches " + regex;
      return contentTypeFilter;
    }
    function tcpFilter(flow) {
      return flow.type === "tcp";
    }
    tcpFilter.desc = "is a TCP Flow";
    function requestContentType(regex) {
      regex = new RegExp(regex, "i");
      function requestContentTypeFilter(flow) {
        return flow.request && regex.test(flowutils.RequestUtils.getContentType(flow.request));
      }
      requestContentTypeFilter.desc = "req. content type matches " + regex;
      return requestContentTypeFilter;
    }
    function responseContentType(regex) {
      regex = new RegExp(regex, "i");
      function responseContentTypeFilter(flow) {
        return flow.response && regex.test(flowutils.ResponseUtils.getContentType(flow.response));
      }
      responseContentTypeFilter.desc = "resp. content type matches " + regex;
      return responseContentTypeFilter;
    }
    function url(regex) {
      regex = new RegExp(regex, "i");
      function urlFilter(flow) {
        return flow.request && regex.test(flowutils.RequestUtils.pretty_url(flow.request));
      }
      urlFilter.desc = "url matches " + regex;
      return urlFilter;
    }
    function websocketFilter(flow) {
      return flow.type === "websocket";
    }
    websocketFilter.desc = "is a Websocket Flow";

    peg$result = peg$startRuleFunction();

    if (peg$result !== peg$FAILED && peg$currPos === input.length) {
      return peg$result;
    } else {
      if (peg$result !== peg$FAILED && peg$currPos < input.length) {
        peg$fail({ type: "end", description: "end of input" });
      }

      throw peg$buildException(null, peg$maxFailExpected, peg$maxFailPos < input.length ? input.charAt(peg$maxFailPos) : null, peg$maxFailPos < input.length ? peg$computeLocation(peg$maxFailPos, peg$maxFailPos + 1) : peg$computeLocation(peg$maxFailPos, peg$maxFailPos));
    }
  }

  return {
    SyntaxError: peg$SyntaxError,
    parse: peg$parse
  };
}();

},{"../flow/utils.js":69}],69:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.isValidHttpVersion = exports.parseUrl = exports.ResponseUtils = exports.RequestUtils = exports.MessageUtils = undefined;

var _lodash = require("lodash");

var _lodash2 = _interopRequireDefault(_lodash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var defaultPorts = {
    "http": 80,
    "https": 443
};

var MessageUtils = exports.MessageUtils = {
    getContentType: function getContentType(message) {
        var ct = this.get_first_header(message, /^Content-Type$/i);
        if (ct) {
            return ct.split(";")[0].trim();
        }
    },
    get_first_header: function get_first_header(message, regex) {
        //FIXME: Cache Invalidation.
        if (!message._headerLookups) Object.defineProperty(message, "_headerLookups", {
            value: {},
            configurable: false,
            enumerable: false,
            writable: false
        });
        if (!(regex in message._headerLookups)) {
            var header;
            for (var i = 0; i < message.headers.length; i++) {
                if (!!message.headers[i][0].match(regex)) {
                    header = message.headers[i];
                    break;
                }
            }
            message._headerLookups[regex] = header ? header[1] : undefined;
        }
        return message._headerLookups[regex];
    },
    match_header: function match_header(message, regex) {
        var headers = message.headers;
        var i = headers.length;
        while (i--) {
            if (regex.test(headers[i].join(" "))) {
                return headers[i];
            }
        }
        return false;
    },
    getContentURL: function getContentURL(flow, message, view) {
        if (message === flow.request) {
            message = "request";
        } else if (message === flow.response) {
            message = "response";
        }
        return "./flows/" + flow.id + "/" + message + "/" + (view ? "content/" + view + ".json" : 'content.data');
    }
};

var RequestUtils = exports.RequestUtils = _lodash2.default.extend(MessageUtils, {
    pretty_url: function pretty_url(request) {
        var port = "";
        if (defaultPorts[request.scheme] !== request.port) {
            port = ":" + request.port;
        }
        return request.scheme + "://" + request.pretty_host + port + request.path;
    }
});

var ResponseUtils = exports.ResponseUtils = _lodash2.default.extend(MessageUtils, {});

var parseUrl_regex = /^(?:(https?):\/\/)?([^\/:]+)?(?::(\d+))?(\/.*)?$/i;
var parseUrl = exports.parseUrl = function parseUrl(url) {
    //there are many correct ways to parse a URL,
    //however, a mitmproxy user may also wish to generate a not-so-correct URL. ;-)
    var parts = parseUrl_regex.exec(url);
    if (!parts) {
        return false;
    }

    var scheme = parts[1],
        host = parts[2],
        port = parseInt(parts[3]),
        path = parts[4];
    if (scheme) {
        port = port || defaultPorts[scheme];
    }
    var ret = {};
    if (scheme) {
        ret.scheme = scheme;
    }
    if (host) {
        ret.host = host;
    }
    if (port) {
        ret.port = port;
    }
    if (path) {
        ret.path = path;
    }
    return ret;
};

var isValidHttpVersion_regex = /^HTTP\/\d+(\.\d+)*$/i;
var isValidHttpVersion = exports.isValidHttpVersion = function isValidHttpVersion(httpVersion) {
    return isValidHttpVersion_regex.test(httpVersion);
};

},{"lodash":"lodash"}],70:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }(); /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          * Instead of dealing with react-router's ever-changing APIs,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          * we use a simple url state manager where we only
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          *
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          * - read the initial URL state on page load
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          * - push updates to the URL later on.
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          */


exports.updateStoreFromUrl = updateStoreFromUrl;
exports.updateUrlFromStore = updateUrlFromStore;
exports.default = initialize;

var _flows = require("./ducks/flows");

var _flow = require("./ducks/ui/flow");

var _eventLog = require("./ducks/eventLog");

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

var Query = {
    SEARCH: "s",
    HIGHLIGHT: "h",
    SHOW_EVENTLOG: "e"
};

function updateStoreFromUrl(store) {
    var _window$location$hash = window.location.hash.substr(1).split("?", 2),
        _window$location$hash2 = _slicedToArray(_window$location$hash, 2),
        path = _window$location$hash2[0],
        query = _window$location$hash2[1];

    var path_components = path.substr(1).split("/");

    if (path_components[0] === "flows") {
        if (path_components.length == 3) {
            var _path_components$slic = path_components.slice(1),
                _path_components$slic2 = _slicedToArray(_path_components$slic, 2),
                flowId = _path_components$slic2[0],
                tab = _path_components$slic2[1];

            store.dispatch((0, _flows.select)(flowId));
            store.dispatch((0, _flow.selectTab)(tab));
        }
    }

    if (query) {
        query.split("&").forEach(function (x) {
            var _x$split = x.split("=", 2),
                _x$split2 = _slicedToArray(_x$split, 2),
                key = _x$split2[0],
                value = _x$split2[1];

            switch (key) {
                case Query.SEARCH:
                    store.dispatch((0, _flows.setFilter)(value));
                    break;
                case Query.HIGHLIGHT:
                    store.dispatch((0, _flows.setHighlight)(value));
                    break;
                case Query.SHOW_EVENTLOG:
                    if (!store.getState().eventLog.visible) store.dispatch((0, _eventLog.toggleVisibility)());
                    break;
                default:
                    console.error("unimplemented query arg: " + x);
            }
        });
    }
}

function updateUrlFromStore(store) {
    var _query;

    var state = store.getState();
    var query = (_query = {}, _defineProperty(_query, Query.SEARCH, state.flows.filter), _defineProperty(_query, Query.HIGHLIGHT, state.flows.highlight), _defineProperty(_query, Query.SHOW_EVENTLOG, state.eventLog.visible), _query);
    var queryStr = Object.keys(query).filter(function (k) {
        return query[k];
    }).map(function (k) {
        return k + "=" + query[k];
    }).join("&");

    var url = void 0;
    if (state.flows.selected.length > 0) {
        url = "/flows/" + state.flows.selected[0] + "/" + state.ui.flow.tab;
    } else {
        url = "/flows";
    }

    if (queryStr) {
        url += "?" + queryStr;
    }
    var pathname = window.location.pathname;
    if (pathname === "blank") {
        pathname = "/"; // this happens in tests...
    }
    if (window.location.hash.substr(1) !== url) {
        history.replaceState(undefined, "", pathname + "#" + url);
    }
}

function initialize(store) {
    updateStoreFromUrl(store);
    store.subscribe(function () {
        return updateUrlFromStore(store);
    });
}

},{"./ducks/eventLog":56,"./ducks/flows":57,"./ducks/ui/flow":61}],71:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.pure = exports.formatTimeStamp = exports.formatTimeDelta = exports.formatSize = exports.Key = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

exports.reverseString = reverseString;
exports.fetchApi = fetchApi;
exports.getDiff = getDiff;

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _react = require('react');

var _react2 = _interopRequireDefault(_react);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

window._ = _lodash2.default;
window.React = _react2.default;

var Key = exports.Key = {
    UP: 38,
    DOWN: 40,
    PAGE_UP: 33,
    PAGE_DOWN: 34,
    HOME: 36,
    END: 35,
    LEFT: 37,
    RIGHT: 39,
    ENTER: 13,
    ESC: 27,
    TAB: 9,
    SPACE: 32,
    BACKSPACE: 8,
    SHIFT: 16
};
// Add A-Z
for (var i = 65; i <= 90; i++) {
    Key[String.fromCharCode(i)] = i;
}

var formatSize = exports.formatSize = function formatSize(bytes) {
    if (bytes === 0) return "0";
    var prefix = ["b", "kb", "mb", "gb", "tb"];
    for (var i = 0; i < prefix.length; i++) {
        if (Math.pow(1024, i + 1) > bytes) {
            break;
        }
    }
    var precision;
    if (bytes % Math.pow(1024, i) === 0) precision = 0;else precision = 1;
    return (bytes / Math.pow(1024, i)).toFixed(precision) + prefix[i];
};

var formatTimeDelta = exports.formatTimeDelta = function formatTimeDelta(milliseconds) {
    var time = milliseconds;
    var prefix = ["ms", "s", "min", "h"];
    var div = [1000, 60, 60];
    var i = 0;
    while (Math.abs(time) >= div[i] && i < div.length) {
        time = time / div[i];
        i++;
    }
    return Math.round(time) + prefix[i];
};

var formatTimeStamp = exports.formatTimeStamp = function formatTimeStamp(seconds) {
    var utc_to_local = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;

    var utc = new Date(seconds * 1000);
    if (utc_to_local) {
        var local = utc.getTime() - utc.getTimezoneOffset() * 60 * 1000;
        var ts = new Date(local).toISOString();
    } else {
        var ts = utc.toISOString();
    }
    return ts.replace("T", " ").replace("Z", "");
};

// At some places, we need to sort strings alphabetically descending,
// but we can only provide a key function.
// This beauty "reverses" a JS string.
var end = String.fromCharCode(0xffff);
function reverseString(s) {
    return String.fromCharCode.apply(String, _lodash2.default.map(s.split(""), function (c) {
        return 0xffff - c.charCodeAt(0);
    })) + end;
}

function getCookie(name) {
    var r = document.cookie.match(new RegExp("\\b" + name + "=([^;]*)\\b"));
    return r ? r[1] : undefined;
}
var xsrf = '_xsrf=' + getCookie("_xsrf");

function fetchApi(url) {
    var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    if (options.method && options.method !== "GET") {
        if (url.indexOf("?") === -1) {
            url += "?" + xsrf;
        } else {
            url += "&" + xsrf;
        }
    } else {
        url += '.json';
    }
    if (url.startsWith("/")) {
        url = "." + url;
    }

    return fetch(url, _extends({
        credentials: 'same-origin'
    }, options));
}

fetchApi.put = function (url, json, options) {
    return fetchApi(url, _extends({
        method: "PUT",
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(json)
    }, options));
};
// deep comparison of two json objects (dicts). arrays are handeled as a single value.
// return: json object including only the changed keys value pairs.
function getDiff(obj1, obj2) {
    var result = _extends({}, obj2);
    for (var key in obj1) {
        if (_lodash2.default.isEqual(obj2[key], obj1[key])) result[key] = undefined;else if (Object.prototype.toString.call(obj2[key]) === '[object Object]' && Object.prototype.toString.call(obj1[key]) === '[object Object]') result[key] = getDiff(obj1[key], obj2[key]);
    }
    return result;
}

var pure = exports.pure = function pure(renderFn) {
    var _class, _temp;

    return _temp = _class = function (_React$PureComponent) {
        _inherits(_class, _React$PureComponent);

        function _class() {
            _classCallCheck(this, _class);

            return _possibleConstructorReturn(this, (_class.__proto__ || Object.getPrototypeOf(_class)).apply(this, arguments));
        }

        _createClass(_class, [{
            key: 'render',
            value: function render() {
                return renderFn(this.props);
            }
        }]);

        return _class;
    }(_react2.default.PureComponent), _class.displayName = renderFn.name, _temp;
};

},{"lodash":"lodash","react":"react"}]},{},[2])

//# sourceMappingURL=app.js.map
