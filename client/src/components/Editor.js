import { Form } from 'react-bootstrap';
import { NavLink } from 'react-router-dom';
import { useState, useEffect, useContext } from 'react';
import Axios from 'axios';
import { AuthorityContext } from './AuthorityContext';
import { checkText } from 'smile2emoji';
import { Dropdown, DropdownButton } from 'react-bootstrap';
import 'react-bootstrap-range-slider/dist/react-bootstrap-range-slider.css';
import RangeSlider from 'react-bootstrap-range-slider';
import BootstrapIcon from '../svg icons/BootstrapIcon';
import { SliderPicker } from 'react-color';
import ReactCrop from 'react-image-crop';
import 'react-image-crop/dist/ReactCrop.css';
import TEMPLATE from '../images/presetFilters/presetTemplate.jpg';
import VINTAGE from '../images/presetFilters/VINTAGE.jpg';
import LOMO from '../images/presetFilters/LOMO.jpg';
import THEA from '../images/presetFilters/THEA.jpg';
import CLARITY from '../images/presetFilters/CLARITY.jpg';
import SINCITY from '../images/presetFilters/SINCITY.jpg';
import SUNRISE from '../images/presetFilters/SUNRISE.jpg';
import CROSSPROCESS from '../images/presetFilters/CROSSPROCESS.jpg';
import ORANGEPEEL from '../images/presetFilters/ORANGEPEEL.jpg';
import LOVE from '../images/presetFilters/LOVE.jpg';
import GRUNGY from '../images/presetFilters/GRUNGY.jpg';
import JARQUES from '../images/presetFilters/JARQUES.jpg';
import PINHOLE from '../images/presetFilters/PINHOLE.jpg';
import OLDBOOT from '../images/presetFilters/OLDBOOT.jpg';
import GLOWINGSUN from '../images/presetFilters/GLOWINGSUN.jpg';
import HAZYDAYS from '../images/presetFilters/HAZYDAYS.jpg';
import HERMAJESTY from '../images/presetFilters/HERMAJESTY.jpg';
import NOSTALGIA from '../images/presetFilters/NOSTALGIA.jpg';
import HEMINGWAY from '../images/presetFilters/HEMINGWAY.jpg';
import CONCENTRATE from '../images/presetFilters/CONCENTRATE.jpg';
import GITHUB from '../images/GitHub.png';
import GITHUBLOGO from '../images/GitHubLogo.png';
import CAMANJS from '../images/camanjs.png';
import CAMERA from '../images/Camera.png';

const Editor = (props) => {
    /* eslint-disable */
    const [userList, setUserList, currentUser, setCurrentUser, url] = useContext(AuthorityContext);
    Axios.defaults.withCredentials = true;
    const [fileInputState, setFileInputState] = useState('');
    const [previewSource, setPreviewSource] = useState('');
    const [isRendering, setIsRendering] = useState(false);
    const [currentRotate, setCurrentRotate] = useState(0);
    const [currentWidth, setCurrentWidth] = useState(100);
    const [currentHeight, setCurrentHeight] = useState(100);
    const [isResettingCrop, setIsResettingCrop] = useState(true);
    const [currentCrop, setCurrentCrop] = useState({
        unit: '%',
        x: 0,
        y: 0,
        width: 100,
        height: 100,
    })
    const cropReset = {
        unit: '%',
        x: 0,
        y: 0,
        width: 100,
        height: 100,
    }
    const [description, setDescription] = useState('');
    const [postView, setPostView] = useState('Public');
    const [isLoading, setIsLoading] = useState(true);
    const [activeTransformContainer, setActiveTransformContainer] = useState(-1);
    const [activeFilterContainer, setActiveFilterContainer] = useState(-1);
    const [currentPreset, setCurrentPreset] = useState('');
    const [previousPreset, setPreviousPreset] = useState('initial');
    const [currentColor, setCurrentColor] = useState('#B3DEE5');
    const [endColor, setEndColor] = useState('#B3DEE5');
    const [currentVignetteSize, setCurrentVignetteSize] = useState(0);
    const [currentVignetteStrength, setCurrentVignetteStrength] = useState(0);
    const [isPNG, setIsPNG] = useState(false);
    const [imageQuality, setImageQuality] = useState(0.8);
    const [maxSize, setMaxSize] = useState(500);
    const [expand, setExpand] = useState(false);
    const [resizeClass, setResizeClass] = useState('');
    const [resizeClassCropped, setResizeClassCropped] = useState('');
    const [postOriginal, setPostOriginal] = useState(false);
    const [renderPaused, setRenderPaused] = useState(false);
    const [fileName, setFileName] = useState("");
    const [values, setValues] = useState({
        brightness: 0,          //-100 .. 100
        contrast: 0,            //-100 .. 100
        exposure: 0,            //-100 .. 100
        stackBlur: 0,           //   0 .. 20

        saturation: 0,          //-100 .. 100
        vibrance: 0,            //-100 .. 100
        hue: 0,                 //   0 .. 100
        clip: 0,                //   0 .. 100

        channelR: 0,            //-100 .. 100 
        channelG: 0,            //-100 .. 100 
        channelB: 0,            //-100 .. 100 
        greyscale: false,       //true .. false

        colorizeStrength: 0,    //   0 .. 100

        gamma: 1,               //   0 .1. 5
        presetFilter: '',

        mirrorX: 0,             //   0 .. 1
        mirrorY: 0,             //   0 .. 1

        resizeWidth: 100,       //   1 .. 100%
        resizeHeight: 100,      //   1 .. 100%

        rotateAngle: 0,         //   0 .. 360

        opacity: 1,             //   0 .. 1

        vignetteSize: 0,        //   0 .. 100%
        vignetteStrength: 0,    //   0 .. 100
        sepia: 0,               //   0 .. 100
        noise: 0,               //   0 .. 100
        invert: false,          //true .. false
        dither: false,          //true .. false
        ditherAlgo: 0,          //   0 .. 7
        sharpen: 0,             //   0 .. 120
        radialBlur: 0,          //   0 .. 8
        motionBlurAngle: 45,    //   0 .. 360
        motionBlurLayers: 0,    //   0 .. 6
    });
    const resetValues = {
        brightness: 0,          //-100 .. 100
        contrast: 0,            //-100 .. 100
        exposure: 0,            //-100 .. 100
        stackBlur: 0,           //   0 .. 20

        saturation: 0,          //-100 .. 100
        vibrance: 0,            //-100 .. 100
        hue: 0,                 //   0 .. 100
        clip: 0,                //   0 .. 100

        channelR: 0,            //-100 .. 100 
        channelG: 0,            //-100 .. 100 
        channelB: 0,            //-100 .. 100 
        greyscale: false,       //true .. false

        colorizeStrength: 0,    //   0 .. 100

        gamma: 1,               //   0 .1. 5
        presetFilter: '',

        mirrorX: 0,             //   0 .. 1
        mirrorY: 0,             //   0 .. 1

        resizeWidth: 100,       //   1 .. 100%
        resizeHeight: 100,      //   1 .. 100%

        rotateAngle: 0,         //   0 .. 360

        opacity: 1,             //   0 .. 1

        vignetteSize: 0,        //   0 .. 100%
        vignetteStrength: 0,    //   0 .. 100
        sepia: 0,               //   0 .. 100
        noise: 0,               //   0 .. 100
        invert: false,          //true .. false
        dither: false,          //true .. false
        ditherAlgo: 0,          //   0 .. 7
        sharpen: 0,             //   0 .. 120
        radialBlur: 0,          //   0 .. 8
        motionBlurAngle: 45,    //   0 .. 360
        motionBlurLayers: 0,    //   0 .. 6
    };
    const [userVerified, setUserVerified] = useState(false);
    const [commandStack, setCommandStack] = useState([]);
    const [redoStack, setRedoStack] = useState([]);
    const [isUndoActive, setIsUndoActive] = useState(false);
    const MAX_COMMAND_STACK = 30;
    const commandCodes = ['fi', 'br', 'co', 'ex', 'ga', 'op', 'sa', 'vi', 'hu', 'in', 'se', 'cl', 're', 'gr', 'bl', 'gy', 'hex', 'coS', 'no', 'sh', 'blr', 'rblr', 'di', 'diA', 'mblr', 'mblrA', 'vin', 'vinS', 'cr', 'ro', 'aw', 'ah', 'mx', 'my'];
    var canvas, canvasCopy, presetCopy;
    var ctxPreset, ctxCopy;

    var img = new Image();
    const ditherAlgorithms = [
        "floyd-steinberg",
        "jarvis-judice-ninke",
        "stucki",
        "atkinson",
        "burkes",
        "sierra",
        "two-row-sierra",
        "sierra-lite"
    ];
    let mounted = false;

    useEffect(() => {
        mounted = true;
        canvas = document.getElementById("canvas");
        presetCopy = document.getElementById("presetCopy");
        canvasCopy = document.getElementById("canvasCopy");
        ctxPreset = presetCopy.getContext("2d");
        ctxCopy = canvasCopy.getContext("2d");
        img = new Image();
        setFileName("");
        window.addEventListener('resize', resizeClassCalculate);
        //Creating crop plugin
        window.Caman.Plugin.register("cloneCanvas", function (canvasCopy, newID) {
            var canvas, ctx;
            canvas = document.createElement('canvas');
            cloneAttributes(canvasCopy, canvas);
            if (canvas) {
                canvas.removeAttribute("data-caman-id");
                canvas.setAttribute('id', newID);
            }
            canvas.width = canvasCopy.width;
            canvas.height = canvasCopy.height;
            ctx = canvas.getContext('2d');
            ctx.drawImage(canvasCopy, 0, 0, canvasCopy.width, canvasCopy.height, 0, 0, canvasCopy.width, canvasCopy.height);
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("mirror", function (x, y) {
            if (x !== 1 && y !== 1) return;
            var canvas, ctx;
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            if (canvas) canvas.removeAttribute("data-caman-id");
            canvas.width = this.canvas.width;
            canvas.height = this.canvas.height;
            ctx = canvas.getContext('2d');
            if (x === 1 && y === 1) {
                ctx.scale(-1, -1);
                ctx.drawImage(this.canvas, 0, 0, -this.canvas.width, -this.canvas.height);
            }
            else if (x === 1) {
                ctx.scale(-1, 1);
                ctx.drawImage(this.canvas, 0, 0, -this.canvas.width, this.canvas.height);
            }
            else {
                ctx.scale(1, -1);
                ctx.drawImage(this.canvas, 0, 0, this.canvas.width, -this.canvas.height);
            }
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("crop", function (width, height, x, y) {
            width /= 100;
            height /= 100;
            x /= 100;
            y /= 100;
            var canvas, ctx;
            if (x == null) {
                x = 0;
            }
            if (y == null) {
                y = 0;
            }
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            if (canvas) canvas.removeAttribute("data-caman-id");
            canvas.width = width * this.canvas.width;
            canvas.height = height * this.canvas.height;
            ctx = canvas.getContext('2d');
            ctx.drawImage(this.canvas, x * this.canvas.width, y * this.canvas.height, width * this.canvas.width, height * this.canvas.height, 0, 0, width * this.canvas.width, height * this.canvas.height);
            this.cropCoordinates = {
                x: x,
                y: y
            };
            this.cropped = true;
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("resizePercent", function (newDims) {
            var canvas, ctx;
            if (newDims == null) {
                newDims = null;
            }
            if (newDims === null || ((newDims.width == null) && (newDims.height == null))) {
                console.error("Invalid or missing dimensions given for resize");
                return;
            }
            if (newDims.width == null) {
                newDims.height /= 100;
                newDims.width = newDims.height;
            } else if (newDims.height == null) {
                newDims.width /= 100;
                newDims.height = newDims.width;
            }
            else {
                newDims.width /= 100;
                newDims.height /= 100;
            }
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            if (canvas) canvas.removeAttribute("data-caman-id");
            canvas.width = newDims.width * this.canvas.width;
            canvas.height = newDims.height * this.canvas.height;
            ctx = canvas.getContext('2d');
            ctx.drawImage(this.canvas, 0, 0, this.canvas.width, this.canvas.height, 0, 0, newDims.width * this.canvas.width, newDims.height * this.canvas.height);
            this.resized = true;
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("resize", function (newDims) {
            var canvas, ctx;
            if (newDims == null) {
                newDims = null;
            }
            if (newDims === null || ((newDims.width == null) && (newDims.height == null))) {
                console.error("Invalid or missing dimensions given for resize");
                return;
            }
            if (newDims.width === 0 || newDims.height === 0) return;
            if (newDims.width == null) {
                newDims.width = this.canvas.width * newDims.height / this.canvas.height;
            } else if (newDims.height == null) {
                newDims.height = this.canvas.height * newDims.width / this.canvas.width;
            }
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            if (canvas) canvas.removeAttribute("data-caman-id");
            canvas.width = newDims.width;
            canvas.height = newDims.height;
            ctx = canvas.getContext('2d');
            ctx.drawImage(this.canvas, 0, 0, this.canvas.width, this.canvas.height, 0, 0, newDims.width, newDims.height);
            this.resized = true;
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("rotate", function (degrees) {
            var angle, canvas, ctx, height, to_radians, width;
            angle = degrees % 360;
            if (angle === 0) {
                return this.dimensions = {
                    width: this.canvas.width,
                    height: this.canvas.height
                };
            }
            to_radians = Math.PI / 180;
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            width = this.canvas.width;
            height = this.canvas.height;
            if (angle === 90 || angle === -90 || angle === 270 || angle === -270) {
                canvas.width = height;
                canvas.height = width;
            }
            else if (angle === 180 || angle === -180) {
                canvas.width = width;
                canvas.height = height;
            }
            else {
                canvas.width = width > height ? width : height;
                canvas.height = width > height ? width : height;
            }
            ctx = canvas.getContext('2d');
            //ctx.save();
            if (angle === 90 || angle === -90 || angle === 270 || angle === -270) {
                ctx.translate(height / 2, width / 2);
            }
            else if (angle === 180 || angle === -180) {
                ctx.translate(width / 2, height / 2);
            }
            else {
                if (width > height) ctx.translate(width / 2, width / 2);
                else ctx.translate(height / 2, height / 2);
            }
            ctx.rotate(angle * to_radians);
            ctx.translate(-width / 2, -height / 2);
            ctx.drawImage(this.canvas, 0, 0, width, height);
            //ctx.restore();


            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("opacity", function (opacity) {
            if (opacity === null || opacity > 1 || opacity < 0) return;
            var canvas, ctx;
            canvas = document.createElement('canvas');
            cloneAttributes(this.canvas, canvas);
            if (canvas) canvas.removeAttribute("data-caman-id");
            canvas.width = this.canvas.width;
            canvas.height = this.canvas.height;
            ctx = canvas.getContext('2d');
            ctx.globalAlpha = opacity;
            ctx.drawImage(this.canvas, 0, 0, this.canvas.width, this.canvas.height);
            return this.replaceCanvas(canvas);
        });

        window.Caman.Plugin.register("dither", function (algo) {
            var algos, b, clampedVal, curAlgo, error, errorX, errorY, g, height, i, ind, isBlack, j, luminance, matrixWidthAdj, newVal, output, pixels, r, value, width, x, y, _i, _j, _k, _l, _m, _n, _o, _p, _ref, _ref1;
            pixels = this.pixelData;
            width = this.dimensions.width;
            height = this.dimensions.height;
            output = (function () {
                var _i, _results;
                _results = [];
                for (i = _i = 0; 0 <= width ? _i < width : _i > width; i = 0 <= width ? ++_i : --_i) {
                    _results.push((function () {
                        var _j, _results1;
                        _results1 = [];
                        for (j = _j = 0; 0 <= height ? _j < height : _j > height; j = 0 <= height ? ++_j : --_j) {
                            _results1.push(0);
                        }
                        return _results1;
                    })());
                }
                return _results;
            })();
            algos = {
                "floyd-steinberg": {
                    matrix: [[0, 0, 7], [3, 5, 1]],
                    divisor: 16
                },
                "jarvis-judice-ninke": {
                    matrix: [[0, 0, 0, 7, 5], [3, 5, 7, 5, 3], [1, 3, 5, 3, 1]],
                    divisor: 48
                },
                "stucki": {
                    matrix: [[0, 0, 0, 8, 4], [2, 4, 8, 4, 2], [1, 2, 4, 2, 1]],
                    divisor: 42
                },
                "atkinson": {
                    matrix: [[0, 0, 0, 1, 1], [0, 1, 1, 1, 0], [0, 0, 1, 0, 0]],
                    divisor: 8
                },
                "burkes": {
                    matrix: [[0, 0, 0, 8, 4], [2, 4, 8, 4, 2]],
                    divisor: 32
                },
                "sierra": {
                    matrix: [[0, 0, 0, 5, 3], [2, 4, 5, 4, 2], [0, 2, 3, 2, 0]],
                    divisor: 32
                },
                "two-row-sierra": {
                    matrix: [[0, 0, 0, 4, 3], [1, 2, 3, 2, 1]],
                    divisor: 16
                },
                "sierra-lite": {
                    matrix: [[0, 0, 2], [1, 1, 0]],
                    divisor: 4
                }
            };
            curAlgo = algos[algo];
            matrixWidthAdj = Math.floor(curAlgo.matrix[0].length / 2);
            ind = (function (_this) {
                return function (x, y) {
                    return (y * width + x) * 4;
                };
            })(this);
            for (y = _i = 0; 0 <= height ? _i < height : _i > height; y = 0 <= height ? ++_i : --_i) {
                for (x = _j = 0; 0 <= width ? _j < width : _j > width; x = 0 <= width ? ++_j : --_j) {
                    r = pixels[ind(x, y)];
                    g = pixels[ind(x, y) + 1];
                    b = pixels[ind(x, y) + 2];
                    luminance = (0.2126 * r) + (0.7152 * g) + (0.0722 * b);
                    output[x][y] = luminance;
                }
            }
            for (y = _k = 0; 0 <= height ? _k < height : _k > height; y = 0 <= height ? ++_k : --_k) {
                for (x = _l = 0; 0 <= width ? _l < width : _l > width; x = 0 <= width ? ++_l : --_l) {
                    newVal = output[x][y] > 128 ? 255 : 0;
                    clampedVal = Math.max(0, Math.min(output[x][y], 255));
                    error = (clampedVal - newVal) / curAlgo.divisor;
                    output[x][y] = newVal;
                    for (i = _m = 0, _ref = curAlgo.matrix.length; 0 <= _ref ? _m < _ref : _m > _ref; i = 0 <= _ref ? ++_m : --_m) {
                        for (j = _n = 0, _ref1 = curAlgo.matrix[i].length; 0 <= _ref1 ? _n < _ref1 : _n > _ref1; j = 0 <= _ref1 ? ++_n : --_n) {
                            errorX = x + j - matrixWidthAdj;
                            errorY = y + i;
                            if (!(errorX < 0 || errorX >= width || errorY >= height)) {
                                output[errorX][errorY] += error * curAlgo.matrix[i][j];
                            }
                        }
                    }
                }
            }
            for (y = _o = 0; 0 <= height ? _o < height : _o > height; y = 0 <= height ? ++_o : --_o) {
                for (x = _p = 0; 0 <= width ? _p < width : _p > width; x = 0 <= width ? ++_p : --_p) {
                    isBlack = output[x][y] < 128;
                    value = isBlack ? 0 : 255;
                    pixels[ind(x, y)] = value;
                    pixels[ind(x, y) + 1] = value;
                    pixels[ind(x, y) + 2] = value;
                }
            }
            return this;
        });

        window.Caman.Filter.register("cloneCanvas", function () {
            return this.processPlugin("cloneCanvas", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("mirror", function () {
            return this.processPlugin("mirror", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("crop", function () {
            return this.processPlugin("crop", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("resizePercent", function () {
            return this.processPlugin("resizePercent", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("resize", function () {
            return this.processPlugin("resize", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("rotate", function () {
            return this.processPlugin("rotate", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("opacity", function () {
            return this.processPlugin("opacity", Array.prototype.slice.call(arguments, 0));
        });

        window.Caman.Filter.register("compoundMotionBlur", function (layers, degrees) {
            if (layers === null || layers < 1) return;
            for (var i = 0; i < layers; i++) {
                this.motionBlur(degrees);
            }
        });

        window.Caman.Filter.register("compoundRadialBlur", function (layers) {
            if (layers === null || layers < 1) return;
            for (var i = 0; i < layers; i++) {
                this.radialBlur();
            }
        });

        window.Caman.Filter.register("thea", function () {
            this.channels({ red: 0, green: 0, blue: 15 })
                .vibrance(50)
                .sepia(10)
                .contrast(5)
                .vignette("61%", 30);
        });

        window.Caman.Filter.register("motionBlur", function (degrees) {
            var kernel;
            degrees %= 360;
            if (degrees === 0 || degrees === 180) {
                kernel = [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0];
            } else if ((degrees > 0 && degrees < 90) || (degrees > 180 && degrees < 270)) {
                kernel = [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0];
            } else if (degrees === 90 || degrees === 270) {
                kernel = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            } else {
                kernel = [1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1];
            }
            return this.processKernel("Motion Blur", kernel);
        });

        window.Caman.Filter.register("sharpen", function (amt) {
            if (amt == null) {
                amt = 100;
            }
            amt /= 100;
            return this.processKernel("Sharpen", [0, -amt, 0, -amt, 4 * amt + 1, -amt, 0, -amt, 0]);
        });

        window.Caman.Filter.register("dither", function (algo) {
            if (algo == null) {
                algo = "floyd-steinberg";
            }
            return this.processPlugin("dither", [algo]);
        });

        window.Caman.Filter.register("dither", function (algo) {
            if (algo == null) {
                algo = "floyd-steinberg";
            }
            return this.processPlugin("dither", [algo]);
        });

        setIsLoading(false);
        return () => mounted = false;
    }, []);

    useEffect(() => {
        mounted = true;
        if (currentUser) setUserVerified(currentUser.verified === 'verified' ? true : false);
        return () => mounted = false;
    }, [currentUser, setCurrentUser])

    useEffect(() => {
        mounted = true;
        if (!isRendering && !renderPaused) {
            setIsRendering(true);
            if (currentPreset !== previousPreset) {
                window.Caman("#presetCopy", img, function () {
                    //this.resize(this.canvas.width > this.canvas.height ? { width: 500 } : { height: 500 })
                    this.revert(false);

                    switch (currentPreset) {
                        case 'vintage': this.vintage(); break;
                        case 'lomo': this.lomo(); break;
                        case 'thea': this.thea(); break;
                        case 'clarity': this.clarity(); break;
                        case 'sinCity': this.sinCity(); break;
                        case 'sunrise': this.sunrise(); break;
                        case 'crossProcess': this.crossProcess(); break;
                        case 'orangePeel': this.orangePeel(); break;
                        case 'love': this.love(); break;
                        case 'grungy': this.grungy(); break;
                        case 'jarques': this.jarques(); break;
                        case 'pinhole': this.pinhole(); break;
                        case 'oldBoot': this.oldBoot(); break;
                        case 'glowingSun': this.glowingSun(); break;
                        case 'hazyDays': this.hazyDays(); break;
                        case 'herMajesty': this.herMajesty(); break;
                        case 'nostalgia': this.nostalgia(); break;
                        case 'hemingway': this.hemingway(); break;
                        case 'concentrate': this.concentrate(); break;
                        default: break;
                    }
                    this.render(function () {
                        copyCanvas();
                    });
                });
            }
            else {
                copyCanvas();
            }
        }
        //eslint-disable-next-line
        return () => mounted = false;
        //eslint-disable-next-line
    }, [values, endColor, renderPaused]);


    function copyCanvas() {
        presetCopy = document.getElementById("presetCopy");
        if (presetCopy) {
            window.Caman("#canvasCopy", img, function () {
                this.revert(false)
                //this.resize(this.canvas.width > this.canvas.height ? { width: 500 } : { height: 500 })
                this.cloneCanvas(presetCopy, "canvasCopy");
                if (values.channelR !== 0 || values.channelG !== 0 || values.channelB !== 0) this.channels({ red: values.channelR, green: values.channelG, blue: values.channelB });
                if (values.saturation !== 0) this.saturation(values.saturation);
                if (values.vibrance !== 0) this.vibrance(values.vibrance);
                if (values.sepia !== 0) this.sepia(values.sepia);
                if (values.clip !== 0) this.clip(values.clip);
                if (values.noise !== 0) this.noise(values.noise);
                if (values.contrast !== 0) this.contrast(values.contrast);
                if (values.exposure !== 0) this.exposure(values.exposure);
                if (values.gamma !== 1) this.gamma(values.gamma);
                if (values.hue !== 0) this.hue(values.hue);
                if (values.greyscale) this.greyscale();
                if (values.colorizeStrength !== 0) this.colorize(endColor, values.colorizeStrength);
                if (values.sharpen !== 0) this.sharpen(values.sharpen);
                if (values.dither) this.dither(ditherAlgorithms[values.ditherAlgo]);
                if (values.invert) this.invert();
                if (values.brightness !== 0) this.brightness(values.brightness);
                if (values.motionBlurLayers !== 0) this.compoundMotionBlur(values.motionBlurLayers, values.motionBlurAngle);
                if (values.radialBlur !== 0) this.compoundRadialBlur(values.radialBlur);
                if (values.stackBlur !== 0) this.stackBlur(values.stackBlur);
                this.render(function () {
                    cropCanvas();
                });
            });
        }
    }

    function cropCanvas() {
        if (currentCrop.width && currentCrop.height) {
            canvasCopy = document.getElementById("canvasCopy");
            window.Caman("#canvas", img, function () {
                if (values.mirrorX === 1 || values.mirrorY === 1) {
                    this.cloneCanvas(canvasCopy, "canvas")
                        //.resize((currentCrop.width / 100) * this.canvas.width > (currentCrop.height / 100) * this.canvas.height ? { width: 500 } : { height: 500 })
                        .opacity(values.opacity)
                        .crop(currentCrop.width, currentCrop.height, currentCrop.x, currentCrop.y)
                        .mirror(values.mirrorX, values.mirrorY)
                        .resizePercent({ width: values.resizeWidth, height: values.resizeHeight })
                        .rotate(values.rotateAngle)

                    if (values.vignetteSize !== 0 && values.vignetteStrength !== 0) this.vignette(values.vignetteSize + '%', values.vignetteStrength);
                    this.render(function () {
                        if ((activeTransformContainer === 0 || activeTransformContainer === 1) && document.getElementById('canvas')) document.getElementById('canvas').classList.add('invisible');
                        setPreviousPreset(values.presetFilter);
                        resizeClassCalculate();
                        setIsRendering(false);
                    });
                }
                else {
                    this.cloneCanvas(canvasCopy, "canvas")
                        //.resize((currentCrop.width / 100) * this.canvas.width > (currentCrop.height / 100) * this.canvas.height ? { width: 500 } : { height: 500 })
                        .opacity(values.opacity)
                        .crop(currentCrop.width, currentCrop.height, currentCrop.x, currentCrop.y)
                        .resizePercent({ width: values.resizeWidth, height: values.resizeHeight })
                        .rotate(values.rotateAngle)
                    if (values.vignetteSize !== 0 && values.vignetteStrength !== 0) this.vignette(values.vignetteSize + '%', values.vignetteStrength);
                    this.render(function () {
                        if ((activeTransformContainer === 0 || activeTransformContainer === 1) && document.getElementById('canvas')) document.getElementById('canvas').classList.add('invisible');
                        setPreviousPreset(values.presetFilter);
                        resizeClassCalculate();
                        setIsRendering(false);
                    });
                }
            });
        }
    }

    useEffect(() => {
        mounted = true;
        var c = document.getElementById('canvas');
        if (c) {
            if (activeTransformContainer === 0 || activeTransformContainer === 1) {
                c.classList.add('invisible');
            }
            else {
                c.classList.remove('invisible');
            }
        }
        return () => mounted = false;
    }, [activeTransformContainer])

    useEffect(() => {
        mounted = true;
        setCurrentRotate(values.rotateAngle);
        return () => mounted = false;
    }, [values.rotateAngle]);
    useEffect(() => {
        mounted = true;
        setCurrentWidth(values.resizeWidth);
        return () => mounted = false;
    }, [values.resizeWidth]);
    useEffect(() => {
        mounted = true;
        setCurrentHeight(values.resizeHeight);
        return () => mounted = false;
    }, [values.resizeHeight]);
    useEffect(() => {
        mounted = true;
        setValues((prevState) => ({
            ...prevState,
            presetFilter: currentPreset
        }))
        return () => mounted = false;
    }, [currentPreset]);
    useEffect(() => {
        setCurrentVignetteSize(values.vignetteSize);
    }, [values.vignetteSize]);
    useEffect(() => {
        setCurrentVignetteStrength(values.vignetteStrength);
    }, [values.vignetteStrength]);
    useEffect(() => {
        mounted = true;
        setMinimizedDimensions();
        return () => mounted = false;
    }, [expand]);
    useEffect(() => {
        if (!isResettingCrop) {
            cropCanvas();
            setIsResettingCrop(true);
        }
    }, [isResettingCrop]);



    function cloneAttributes(sourceNode, element) {
        let attr;
        let attributes = Array.prototype.slice.call(sourceNode.attributes);
        //eslint-disable-next-line
        while (attr = attributes.pop()) {
            element.setAttribute(attr.nodeName, attr.nodeValue);
        }
    }

    function setMinimizedDimensions() {
        let canvasCopy = document.getElementById("canvasCopy").getBoundingClientRect();
        let rootElement = document.documentElement;
        if (rootElement && canvasCopy) {
            rootElement.style.setProperty('--minimized-width', canvasCopy.width + 'px');
            rootElement.style.setProperty('--minimized-height', canvasCopy.height + 'px');
        }
    }

    function resizeClassCalculate() {
        if (!document.getElementById('presetCopy') || !document.getElementById('canvas') || !document.getElementById('canvasCover')) return;
        var presetCopy = document.getElementById('presetCopy').getBoundingClientRect();
        var canvas = document.getElementById('canvas');
        var canvasScreen = document.getElementById('canvasCover').getBoundingClientRect();
        if (presetCopy && canvasScreen && (presetCopy.width * presetCopy.height !== 0) && (canvasScreen.width * canvasScreen.height !== 0)) {
            //console.log((presetCopy.width/presetCopy.height).toString() + ' - ' + (canvasScreen.width/canvasScreen.height).toString() + ' = ' + ((presetCopy.width/presetCopy.height)-(canvasScreen.width/canvasScreen.height)).toString())
            setResizeClass((presetCopy.width / presetCopy.height) - (canvasScreen.width / canvasScreen.height) > 0 ? 'autoHeight' : 'autoWidth');
        }
        else setResizeClass('');
        if (canvas && canvasScreen && (canvas.width * canvas.height !== 0) && (canvasScreen.width * canvasScreen.height !== 0)) {
            //console.log((canvas.width/canvas.height).toString() + ' - ' + (canvasScreen.width/canvasScreen.height).toString() + ' = ' + ((canvas.width/canvas.height)-(canvasScreen.width/canvasScreen.height)).toString())
            setResizeClassCropped((canvas.width / canvas.height) - (canvasScreen.width / canvasScreen.height) > 0 ? 'autoHeightCropped' : 'autoWidthCropped');
        }
        else setResizeClassCropped('');
        setMinimizedDimensions();
    }

    useEffect(() => {
        if (!isUndoActive) addCommand('Fi:' + currentPreset);
        else setIsUndoActive(false);
    }, [currentPreset]);
    useEffect(() => {
        if (!isUndoActive) addCommand('br:' + values.brightness);
        else setIsUndoActive(false);
    }, [values.brightness]);
    useEffect(() => {
        if (!isUndoActive) addCommand('co:' + values.contrast);
        else setIsUndoActive(false);
    }, [values.contrast]);
    useEffect(() => {
        if (!isUndoActive) addCommand('ex:' + values.exposure);
        else setIsUndoActive(false);
    }, [values.exposure]);
    useEffect(() => {
        if (!isUndoActive) addCommand('ga:' + values.gamma);
        else setIsUndoActive(false);
    }, [values.gamma]);
    useEffect(() => {
        if (!isUndoActive) addCommand('op:' + values.opacity);
        else setIsUndoActive(false);
    }, [values.opacity]);
    useEffect(() => {
        if (!isUndoActive) addCommand('sa:' + values.saturation);
        else setIsUndoActive(false);
    }, [values.saturation]);
    useEffect(() => {
        if (!isUndoActive) addCommand('vi:' + values.vibrance);
        else setIsUndoActive(false);
    }, [values.vibrance]);
    useEffect(() => {
        if (!isUndoActive) addCommand('hu:' + values.hue);
        else setIsUndoActive(false);
    }, [values.hue]);
    useEffect(() => {
        if (!isUndoActive) addCommand('in:' + (values.invert ? 1 : 0));
        else setIsUndoActive(false);
    }, [values.invert]);
    useEffect(() => {
        if (!isUndoActive) addCommand('se:' + values.sepia);
        else setIsUndoActive(false);
    }, [values.sepia]);
    useEffect(() => {
        if (!isUndoActive) addCommand('cl:' + values.clip);
        else setIsUndoActive(false);
    }, [values.clip]);
    useEffect(() => {
        if (!isUndoActive) addCommand('re:' + values.channelR);
        else setIsUndoActive(false);
    }, [values.channelR]);
    useEffect(() => {
        if (!isUndoActive) addCommand('gr:' + values.channelG);
        else setIsUndoActive(false);
    }, [values.channelG]);
    useEffect(() => {
        if (!isUndoActive) addCommand('bl:' + values.channelB);
        else setIsUndoActive(false);
    }, [values.channelB]);
    useEffect(() => {
        if (!isUndoActive) addCommand('gy:' + (values.greyscale ? 1 : 0));
        else setIsUndoActive(false);
    }, [values.greyscale]);
    useEffect(() => {
        if (!isUndoActive) addCommand('hex:' + endColor);
        else setIsUndoActive(false);
    }, [endColor]);
    useEffect(() => {
        if (!isUndoActive) addCommand('coS:' + values.colorizeStrength);
        else setIsUndoActive(false);
    }, [values.colorizeStrength]);
    useEffect(() => {
        if (!isUndoActive) addCommand('no:' + values.noise);
        else setIsUndoActive(false);
    }, [values.noise]);
    useEffect(() => {
        if (!isUndoActive) addCommand('sh:' + values.sharpen);
        else setIsUndoActive(false);
    }, [values.sharpen]);
    useEffect(() => {
        if (!isUndoActive) addCommand('blr:' + values.stackBlur);
        else setIsUndoActive(false);
    }, [values.stackBlur]);
    useEffect(() => {
        if (!isUndoActive) addCommand('rblr:' + values.radialBlur);
        else setIsUndoActive(false);
    }, [values.radialBlur]);
    useEffect(() => {
        if (!isUndoActive) addCommand('di:' + (values.dither ? 1 : 0));
        else setIsUndoActive(false);
    }, [values.dither]);
    useEffect(() => {
        if (!isUndoActive) addCommand('diA:' + values.ditherAlgo);
        else setIsUndoActive(false);
    }, [values.ditherAlgo]);
    useEffect(() => {
        if (!isUndoActive) addCommand('mblr:' + values.motionBlurLayers);
        else setIsUndoActive(false);
    }, [values.motionBlurLayers]);
    useEffect(() => {
        if (!isUndoActive) addCommand('mblrA:' + values.motionBlurAngle);
        else setIsUndoActive(false);
    }, [values.motionBlurAngle]);
    useEffect(() => {
        if (!isUndoActive && (currentVignetteSize !== values.vignetteSize)) addCommand('vin:' + values.vignetteSize);
        else setIsUndoActive(false);
    }, [values.vignetteSize]);
    useEffect(() => {
        if (!isUndoActive && (currentVignetteStrength !== values.vignetteStrength)) addCommand('vinS:' + values.vignetteStrength);
        else setIsUndoActive(false);
    }, [values.vignetteStrength]);
    function addCropCommand() {
        addCommand('cr:' + currentCrop.width.toFixed(2) + ':' + currentCrop.height.toFixed(2) + ':' + currentCrop.x.toFixed(2) + ':' + currentCrop.y.toFixed(2));
    }
    useEffect(() => {
        if (!isUndoActive) addCommand('ro:' + values.rotateAngle);
        else setIsUndoActive(false);
    }, [values.rotateAngle]);
    useEffect(() => {
        if (!isUndoActive) addCommand('aw:' + values.resizeWidth);
        else setIsUndoActive(false);
    }, [values.resizeWidth]);
    useEffect(() => {
        if (!isUndoActive) addCommand('ah:' + values.resizeHeight);
        else setIsUndoActive(false);
    }, [values.resizeHeight]);
    useEffect(() => {
        if (!isUndoActive) addCommand('mx:' + values.mirrorX);
        else setIsUndoActive(false);
    }, [values.mirrorX]);
    useEffect(() => {
        if (!isUndoActive) addCommand('my:' + values.mirrorY);
        else setIsUndoActive(false);
    }, [values.mirrorY]);


    /* eslint-enable */


    function addCommand(command) {
        if (command !== commandStack[commandStack.length - 1]) {
            let newCommandStack = [...commandStack];
            if (newCommandStack.push(command) > MAX_COMMAND_STACK) newCommandStack.shift();
            setCommandStack([...newCommandStack]);
            setRedoStack([]);
        }
    }

    function undoCommand() {
        if (commandStack.length > 0) {
            setIsUndoActive(true);
            parseUndo(commandStack[commandStack.length - 1]);
            let newCommandStack = [...commandStack];
            let newRedoStack = [...redoStack, newCommandStack.pop()];
            setRedoStack([...newRedoStack]);
            setCommandStack([...newCommandStack]);
        }
    }

    function redoCommand() {
        if (redoStack.length > 0) {
            setIsUndoActive(true);
            parseRedo(redoStack[redoStack.length - 1]);
            let newRedoStack = [...redoStack];
            let newCommandStack = [...commandStack, newRedoStack.pop()];
            setRedoStack([...newRedoStack]);
            setCommandStack([...newCommandStack]);
        }
    }



    function parseUndo(command) {
        var i, commandValues;
        for (i = commandStack.length - 2; i >= 0; i--) {
            if (commandStack[i].split(':', 1)[0] === command.split(':', 1)[0]) {
                break;
            }
        }
        commandValues = i !== -1 ? commandStack[i].split(':') : [];
        switch (command.split(':', 1)[0]) {
            case 'Fi': setPreviousPreset(commandValues.length > 0 ? values.presetFilter : 'initial');
                setCurrentPreset(commandValues.length > 0 ? commandValues[1] : resetValues.presetFilter)
                break;
            case 'br': setValues((prevState) => ({
                ...prevState,
                brightness: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.brightness
            }))
                break;
            case 'co': setValues((prevState) => ({
                ...prevState,
                contrast: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.contrast
            }))
                break;
            case 'ex': setValues((prevState) => ({
                ...prevState,
                exposure: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.exposure
            }))
                break;
            case 'ga': setValues((prevState) => ({
                ...prevState,
                gamma: commandValues.length > 0 ? parseFloat((parseFloat(commandValues[1]).toFixed(1))) : resetValues.gamma
            }))
                break;
            case 'op': setValues((prevState) => ({
                ...prevState,
                opacity: commandValues.length > 0 ? parseFloat((parseFloat(commandValues[1]).toFixed(2))) : resetValues.opacity
            }))
                break;
            case 'sa': setValues((prevState) => ({
                ...prevState,
                saturation: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.saturation
            }))
                break;
            case 'vi': setValues((prevState) => ({
                ...prevState,
                vibrance: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vibrance
            }))
                break;
            case 'hu': setValues((prevState) => ({
                ...prevState,
                hue: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.hue
            }))
                break;
            case 'in': setValues((prevState) => ({
                ...prevState,
                invert: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'se': setValues((prevState) => ({
                ...prevState,
                sepia: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.sepia
            }))
                break;
            case 'cl': setValues((prevState) => ({
                ...prevState,
                clip: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.clip
            }))
                break;
            case 're': setValues((prevState) => ({
                ...prevState,
                channelR: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelR
            }))
                break;
            case 'gr': setValues((prevState) => ({
                ...prevState,
                channelG: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelG
            }))
                break;
            case 'bl': setValues((prevState) => ({
                ...prevState,
                channelB: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelB
            }))
                break;
            case 'gy': setValues((prevState) => ({
                ...prevState,
                greyscale: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'hex': setCurrentColor(commandValues.length > 0 ? commandValues[1] : '#B3DEE5');
                setEndColor(commandValues.length > 0 ? commandValues[1] : '#B3DEE5');
                break;
            case 'coS': setValues((prevState) => ({
                ...prevState,
                colorizeStrength: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.colorizeStrength
            }))
                break;
            case 'no': setValues((prevState) => ({
                ...prevState,
                noise: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.noise
            }))
                break;
            case 'sh': setValues((prevState) => ({
                ...prevState,
                sharpen: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.sharpen
            }))
                break;
            case 'blr': setValues((prevState) => ({
                ...prevState,
                stackBlur: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.stackBlur
            }))
                break;
            case 'rblr': setValues((prevState) => ({
                ...prevState,
                radialBlur: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.radialBlur
            }))
                break;
            case 'di': setValues((prevState) => ({
                ...prevState,
                dither: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'diA': setValues((prevState) => ({
                ...prevState,
                ditherAlgo: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.ditherAlgo
            }))
                break;
            case 'mblr': setValues((prevState) => ({
                ...prevState,
                motionBlurLayers: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.motionBlurLayers
            }))
                break;
            case 'mblrA': setValues((prevState) => ({
                ...prevState,
                motionBlurAngle: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.motionBlurAngle
            }))
                break;
            case 'vin': setValues((prevState) => ({
                ...prevState,
                vignetteSize: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vignetteSize
            }))
                break;
            case 'vinS': setValues((prevState) => ({
                ...prevState,
                vignetteStrength: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vignetteStrength
            }))
                break;
            case 'cr': setCurrentCrop(commandValues.length > 0 ?
                {
                    unit: '%',
                    width: parseInt(commandValues[1]),
                    height: parseInt(commandValues[2]),
                    x: parseInt(commandValues[3]),
                    y: parseInt(commandValues[4]),
                }
                : { ...cropReset }
            )
                setIsResettingCrop(false);
                break;
            case 'ro': setValues((prevState) => ({
                ...prevState,
                rotateAngle: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.rotateAngle
            }))
                break;
            case 'aw': setValues((prevState) => ({
                ...prevState,
                resizeWidth: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.resizeWidth
            }))
                break;
            case 'ah': setValues((prevState) => ({
                ...prevState,
                resizeHeight: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.resizeHeight
            }))
                break;
            case 'mx': setValues((prevState) => ({
                ...prevState,
                mirrorX: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? 1 : 0
            }))
                break;
            case 'my': setValues((prevState) => ({
                ...prevState,
                mirrorY: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? 1 : 0
            }))
                break;
            default: break;
            //'fi', 'br', 'co', 'ex', 'ga', 'op', 'sa', 'vi', 'hu', 'in', 'se', 'cl', 're', 'gr', 'bl', 'gy', 'hex', 'coS', 'no', 'sh', 'blr', 'rblr', 'di', 'diA', 'mblr', 'mblrA', 'vin', 'vinS', 'cr', 'ro', 'aw', 'ah', 'mx', 'my'
        }
    }

    function parseRedo(command) {
        var commandValues = command.split(':');
        switch (command.split(':', 1)[0]) {
            case 'Fi': setPreviousPreset(commandValues.length > 0 ? values.presetFilter : 'initial');
                setCurrentPreset(commandValues.length > 0 ? commandValues[1] : resetValues.presetFilter)
                break;
            case 'br': setValues((prevState) => ({
                ...prevState,
                brightness: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.brightness
            }))
                break;
            case 'co': setValues((prevState) => ({
                ...prevState,
                contrast: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.contrast
            }))
                break;
            case 'ex': setValues((prevState) => ({
                ...prevState,
                exposure: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.exposure
            }))
                break;
            case 'ga': setValues((prevState) => ({
                ...prevState,
                gamma: commandValues.length > 0 ? parseFloat((parseFloat(commandValues[1]).toFixed(1))) : resetValues.gamma
            }))
                break;
            case 'op': setValues((prevState) => ({
                ...prevState,
                opacity: commandValues.length > 0 ? parseFloat((parseFloat(commandValues[1]).toFixed(2))) : resetValues.opacity
            }))
                break;
            case 'sa': setValues((prevState) => ({
                ...prevState,
                saturation: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.saturation
            }))
                break;
            case 'vi': setValues((prevState) => ({
                ...prevState,
                vibrance: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vibrance
            }))
                break;
            case 'hu': setValues((prevState) => ({
                ...prevState,
                hue: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.hue
            }))
                break;
            case 'in': setValues((prevState) => ({
                ...prevState,
                invert: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'se': setValues((prevState) => ({
                ...prevState,
                sepia: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.sepia
            }))
                break;
            case 'cl': setValues((prevState) => ({
                ...prevState,
                clip: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.clip
            }))
                break;
            case 're': setValues((prevState) => ({
                ...prevState,
                channelR: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelR
            }))
                break;
            case 'gr': setValues((prevState) => ({
                ...prevState,
                channelG: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelG
            }))
                break;
            case 'bl': setValues((prevState) => ({
                ...prevState,
                channelB: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.channelB
            }))
                break;
            case 'gy': setValues((prevState) => ({
                ...prevState,
                greyscale: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'hex': setCurrentColor(commandValues.length > 0 ? commandValues[1] : '#B3DEE5');
                setEndColor(commandValues.length > 0 ? commandValues[1] : '#B3DEE5');
                break;
            case 'coS': setValues((prevState) => ({
                ...prevState,
                colorizeStrength: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.colorizeStrength
            }))
                break;
            case 'no': setValues((prevState) => ({
                ...prevState,
                noise: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.noise
            }))
                break;
            case 'sh': setValues((prevState) => ({
                ...prevState,
                sharpen: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.sharpen
            }))
                break;
            case 'blr': setValues((prevState) => ({
                ...prevState,
                stackBlur: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.stackBlur
            }))
                break;
            case 'rblr': setValues((prevState) => ({
                ...prevState,
                radialBlur: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.radialBlur
            }))
                break;
            case 'di': setValues((prevState) => ({
                ...prevState,
                dither: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? true : false
            }))
                break;
            case 'diA': setValues((prevState) => ({
                ...prevState,
                ditherAlgo: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.ditherAlgo
            }))
                break;
            case 'mblr': setValues((prevState) => ({
                ...prevState,
                motionBlurLayers: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.motionBlurLayers
            }))
                break;
            case 'mblrA': setValues((prevState) => ({
                ...prevState,
                motionBlurAngle: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.motionBlurAngle
            }))
                break;
            case 'vin': setValues((prevState) => ({
                ...prevState,
                vignetteSize: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vignetteSize
            }))
                break;
            case 'vinS': setValues((prevState) => ({
                ...prevState,
                vignetteStrength: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.vignetteStrength
            }))
                break;
            case 'cr': setCurrentCrop(commandValues.length > 0 ?
                {
                    unit: '%',
                    width: parseInt(commandValues[1]),
                    height: parseInt(commandValues[2]),
                    x: parseInt(commandValues[3]),
                    y: parseInt(commandValues[4]),
                }
                : { ...cropReset }
            )
                setIsResettingCrop(false);
                break;
            case 'ro': setValues((prevState) => ({
                ...prevState,
                rotateAngle: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.rotateAngle
            }))
                break;
            case 'aw': setValues((prevState) => ({
                ...prevState,
                resizeWidth: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.resizeWidth
            }))
                break;
            case 'ah': setValues((prevState) => ({
                ...prevState,
                resizeHeight: commandValues.length > 0 ? parseInt(commandValues[1]) : resetValues.resizeHeight
            }))
                break;
            case 'mx': setValues((prevState) => ({
                ...prevState,
                mirrorX: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? 1 : 0
            }))
                break;
            case 'my': setValues((prevState) => ({
                ...prevState,
                mirrorY: (commandValues.length > 0) && (parseInt(commandValues[1]) === 1) ? 1 : 0
            }))
                break;
            default: break;
            //'fi', 'br', 'co', 'ex', 'ga', 'op', 'sa', 'vi', 'hu', 'in', 'se', 'cl', 're', 'gr', 'bl', 'gy', 'hex', 'coS', 'no', 'sh', 'blr', 'rblr', 'di', 'diA', 'mblr', 'mblrA', 'vin', 'vinS', 'cr', 'ro', 'aw', 'ah', 'mx', 'my'
        }
    }

    // Download
    function download(canvas, filename) {
        // Init event
        let e;
        // Create link
        const link = document.createElement("a");

        // Set props
        link.download = filename;
        link.href = canvas.toDataURL("image/" + (isPNG ? 'png' : 'jpeg'), imageQuality);
        // New mouse event
        e = new MouseEvent("click");
        // Dispatch event
        link.dispatchEvent(e);
    }

    const handleFileInputChange = (e) => {
        const file = e.target.files[0];
        if (file && file.type.match('image.*')) {
            setFileName(file.name);
            previewFile(file);
            setFileInputState(e.target.value);
        }
        else {
            setFileInputState('');
            setPreviewSource('');
            setIsLoading(false);
        }
    }

    const previewFile = (file) => {
        setIsLoading(true);
        const reader = new FileReader();
        reader.readAsDataURL(file);
        canvas = document.getElementById("canvas");
        presetCopy = document.getElementById("presetCopy");
        canvasCopy = document.getElementById("canvasCopy");
        ctxPreset = presetCopy.getContext("2d");
        ctxCopy = canvasCopy.getContext("2d");
        setActiveTransformContainer(-1);
        setExpand(false);
        reader.onloadend = () => {
            setPreviewSource(reader.result);
            window.Caman("#canvasCopy", img, function () {
                this.reloadCanvasData();
            });
            window.Caman("#presetCopy", img, function () {
                this.reloadCanvasData();
                // Create image
                img = new Image();
                // Set image src
                img.src = reader.result;
                // On image load add to canvas
                img.onload = function () {
                    if (img.width > maxSize || img.height > maxSize) {
                        if (img.width > img.height) {
                            presetCopy.width = maxSize;
                            presetCopy.height = maxSize * (img.height / img.width);
                        }
                        else {
                            presetCopy.height = maxSize;
                            presetCopy.width = maxSize * (img.width / img.height);
                        }
                    }
                    else {
                        presetCopy.width = img.width;
                        presetCopy.height = img.height;
                    }
                    ctxPreset.drawImage(img, 0, 0, img.width, img.height, 0, 0, presetCopy.width, presetCopy.height);
                    presetCopy.removeAttribute("data-caman-id");

                    canvasCopy.width = presetCopy.width;
                    canvasCopy.height = presetCopy.height;
                    ctxCopy.drawImage(presetCopy, 0, 0, presetCopy.width, presetCopy.height);
                    canvasCopy.removeAttribute("data-caman-id");
                    setMinimizedDimensions();
                    copyCanvas();

                    setCurrentCrop({ ...cropReset });
                    setPreviousPreset('initial');
                    setCurrentPreset('');
                    setValues({ ...resetValues });
                    setCommandStack([]);
                    setRedoStack([]);
                    setRenderPaused(false);
                    setIsLoading(false);
                };
                /*
                window.Caman.Event.listen("processStart", function (job) {
                });
                window.Caman.Event.listen("processComplete", function (job) {
                    //console.log("Finished:", job.name);
                });
                window.Caman.Event.listen("renderFinished", function () {
                    //console.log("Finished Rendering");
                });
                */
            });
        }
    }

    const postFile = (e) => {
        e.preventDefault();
        if (!previewSource) return;
        canvas = document.getElementById("canvas");
        if (postOriginal) postImage(previewSource);
        else if (canvas) {
            var editedImage = canvas.toDataURL("image/" + (isPNG ? 'png' : 'jpeg'), imageQuality);
            postImage(editedImage);
        }
    }

    const postImage = (base64EncodedImage) => {
        var tempDescription = description;
        var tempPostView = postView;
        setFileInputState('');
        setPreviewSource('');
        setDescription('');
        setPostView('Public');
        setIsLoading(true);
        if (document.getElementById('fileUploadForm')) document.getElementById('fileUploadForm').reset();
        Axios.post(url + '/image/upload/post', {
            data: base64EncodedImage,
            userID: currentUser.id,
            description: tempDescription,
            view: tempPostView
        }).then((response) => {
            props.history.push('/posts/' + response.data[0].id);
            setIsLoading(false);
        })
    }

    return (
        <div>
            <div className="blog-header small-header">
                <div className="container btrans small-btrans">
                    <h1 className="text-center"><strong>Foto Editor</strong></h1>
                </div>
            </div>

            <div className="container">

                <div className="row">

                    <div className="col-sm-12 blog-main">

                        <div className="blog-post">
                            <Form acceptCharset="UTF-8" onSubmit={(e) => { e.preventDefault(); }} id="fileUploadForm">
                                <Form.Group>
                                    <Form.File accept="image/x-png,image/gif,image/jpeg" value={fileInputState} onChange={handleFileInputChange} className="fileUpload" id="fileUploadID" name="image" label="Upload photo" />

                                    <div id="maxImageSizeContainer" className="sliderCoupleContainer">

                                        <div className="sliderCouple">
                                            <div className="sliderFlexWrap">
                                                <p>50px</p>
                                                <RangeSlider
                                                    value={maxSize}
                                                    onChange={(e) => { setMaxSize(e.target.value) }}
                                                    onAfterChange={
                                                        (e) => { setMaxSize(e.target.value) }
                                                    }
                                                    min={50}
                                                    max={1600}
                                                    step={50}
                                                    className="rotateRange"
                                                    variant="light"
                                                    tooltipLabel={currentValue => `${currentValue}px`}
                                                    tooltipPlacement='top'
                                                    tooltip='on'
                                                />
                                                <p>1600px</p>
                                            </div>
                                            <div id="maxSize-add" onClick={() => {
                                                setMaxSize((prevState) => (
                                                    prevState < 1550 ? prevState + 50 : 1600
                                                ))
                                            }} className="valueButton">
                                                +
                                                </div>
                                            <p>Max Size</p>
                                            <div id="maxSize-remove" onClick={() => {
                                                setMaxSize((prevState) => (
                                                    prevState > 100 ? prevState - 50 : 50
                                                ))
                                            }} className="valueButton">
                                                -
                                                </div>
                                        </div>
                                    </div>
                                </Form.Group>

                                <div className="row">
                                    <div className="activeFilterContainer autoLeftBorder">

                                        <div className={"toggle-expandContainer buttonCoupleContainer align-self-center" + (activeTransformContainer === -1 ? '' : ' display-none')}>
                                            <p className="toggle-expand-text">{expand ? 'Minimize' : 'Expand'}</p>
                                            <div id="toggle-expand" onClick={() => { setExpand(!expand); resizeClassCalculate(); }} className={"editorButton" + (expand ? ' activeButton' : '')}><BootstrapIcon type={expand ? 75 : 74} /></div>
                                        </div>

                                        <div className={"toggle-expandContainer buttonCoupleContainer align-self-center" + (activeTransformContainer === 0 ? '' : ' display-none')}>
                                            <p className="toggle-expand-text">Original Image</p>
                                            <div onClick={() => { setExpand(!expand); resizeClassCalculate(); }} className={"editorButton" + (expand ? ' activeButton' : '')}><BootstrapIcon type={expand ? 75 : 74} /></div>
                                        </div>

                                        <div className={"toggle-expandContainer buttonCoupleContainer align-self-center" + (activeTransformContainer === 1 ? '' : ' display-none')}>
                                            <p className="toggle-expand-text">Select Crop Area</p>
                                            <div id="crop-reset" onClick={() => { addCommand('cr:100:100:0:0'); setCurrentCrop({ ...cropReset }); setIsResettingCrop(false); }} className="editorButton"><BootstrapIcon type={82} /></div>
                                            <div onClick={() => { setExpand(!expand); resizeClassCalculate(); }} className={"editorButton" + (expand ? ' activeButton' : '')}><BootstrapIcon type={expand ? 75 : 74} /></div>
                                            <div id="crop-confirm" onClick={() => { setActiveTransformContainer(-1) }} className="editorButton"><BootstrapIcon type={83} /></div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeTransformContainer === 2 ? '' : ' display-none')}>
                                            <p>Rotate</p>
                                            <div className="sliderCouple">
                                                <div className="sliderFlexWrap">

                                                    <RangeSlider
                                                        value={currentRotate}
                                                        onChange={(e) => { setCurrentRotate(e.target.value) }}
                                                        onAfterChange={
                                                            (e) => {
                                                                setValues((prevState) => ({
                                                                    ...prevState,
                                                                    rotateAngle: parseInt(e.target.value)
                                                                }))
                                                            }
                                                        }
                                                        min={-180}
                                                        max={180}
                                                        step={1}
                                                        className="rotateRange"
                                                        variant="light"
                                                        tooltipLabel={currentValue => `${currentValue}°`}
                                                        tooltipPlacement='top'
                                                        tooltip='on'
                                                    />
                                                </div>
                                                <div id="rotate-add" onClick={() => {
                                                    setCurrentRotate(values.rotateAngle < 180 ? values.rotateAngle + 1 : -180);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        rotateAngle: prevState.rotateAngle < 180 ? prevState.rotateAngle + 1 : -180
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <div id="rotate-clockwise" onClick={() => {
                                                    setCurrentRotate(values.rotateAngle === 0 ? 90 : values.rotateAngle === 90 ? 180 : (values.rotateAngle === 180 || values.rotateAngle === -180) ? -90 : 0);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        rotateAngle: prevState.rotateAngle === 0 ? 90 : prevState.rotateAngle === 90 ? -180 : (prevState.rotateAngle === 180 || prevState.rotateAngle === -180) ? -90 : 0
                                                    }))
                                                }} className="valueButton">
                                                    {(values.rotateAngle === 0 || values.rotateAngle === 90 || values.rotateAngle === 180 || values.rotateAngle === -180 || values.rotateAngle === -90) ?
                                                        <BootstrapIcon type={40} />
                                                        : <BootstrapIcon type={39} />
                                                    }
                                                </div>
                                                <div id="rotate-remove" onClick={() => {
                                                    setCurrentRotate(values.rotateAngle > -180 ? values.rotateAngle - 1 : 180);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        rotateAngle: prevState.rotateAngle > -180 ? prevState.rotateAngle - 1 : 180
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>
                                            </div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeTransformContainer === 3 ? '' : ' display-none')}>
                                            <div className="sliderCouple">
                                                <div id="resizeWidth-add" onClick={() => {
                                                    setCurrentWidth(values.resizeWidth < 99 ? values.resizeWidth + 1 : 100);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeWidth: prevState.resizeWidth < 99 ? prevState.resizeWidth + 1 : 100
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <div id="resizeWidth-Original" onClick={() => {
                                                    setCurrentWidth(100);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeWidth: 100
                                                    }))
                                                }} className="valueButton">
                                                    <BootstrapIcon type={42} />
                                                </div>
                                                <div id="resizeWidth-remove" onClick={() => {
                                                    setCurrentWidth(values.resizeWidth > 6 ? values.resizeWidth - 1 : 5);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeWidth: prevState.resizeWidth > 6 ? prevState.resizeWidth - 1 : 5
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>
                                                <div className="sliderFlexWrap Aspect">

                                                    <RangeSlider
                                                        value={currentWidth}
                                                        onChange={(e) => { setCurrentWidth(e.target.value) }}
                                                        onAfterChange={
                                                            (e) => {
                                                                setValues((prevState) => ({
                                                                    ...prevState,
                                                                    resizeWidth: parseInt(e.target.value)
                                                                }))
                                                            }
                                                        }
                                                        min={5}
                                                        max={100}
                                                        step={1}
                                                        className="resizeRange"
                                                        variant="light"
                                                        tooltipLabel={currentValue => `${currentValue}%`}
                                                        tooltipPlacement='top'
                                                        tooltip='auto'
                                                    />
                                                </div>

                                                <div className="sliderFlexWrap Aspect">

                                                    <RangeSlider
                                                        value={currentHeight}
                                                        onChange={(e) => { setCurrentHeight(e.target.value) }}
                                                        onAfterChange={
                                                            (e) => {
                                                                setValues((prevState) => ({
                                                                    ...prevState,
                                                                    resizeHeight: parseInt(e.target.value)
                                                                }))
                                                            }
                                                        }
                                                        min={5}
                                                        max={100}
                                                        step={1}
                                                        className="resizeRange"
                                                        variant="light"
                                                        tooltipLabel={currentValue => `${currentValue}%`}
                                                        tooltipPlacement='bottom'
                                                        tooltip='auto'
                                                    />
                                                </div>
                                                <div id="resizeHeight-add" onClick={() => {
                                                    setCurrentHeight(values.resizeHeight < 99 ? values.resizeHeight + 1 : 100);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeHeight: prevState.resizeHeight < 99 ? prevState.resizeHeight + 1 : 100
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <div id="resizeHeight-Original" onClick={() => {
                                                    setCurrentHeight(100);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeHeight: 100
                                                    }))
                                                }} className="valueButton">
                                                    <BootstrapIcon type={43} />
                                                </div>
                                                <div id="resizeHeight-remove" onClick={() => {
                                                    setCurrentHeight(values.resizeHeight > 6 ? values.resizeHeight - 1 : 5);
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        resizeHeight: prevState.resizeHeight > 6 ? prevState.resizeHeight - 1 : 5
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>

                                            </div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeTransformContainer === 4 ? '' : ' display-none')}>
                                            <p>Mirror</p>
                                            <div className="sliderCouple">
                                                <div id="mirrorY" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        mirrorY: prevState.mirrorY === 0 ? 1 : 0
                                                    }))
                                                }} className={"valueButton" + (values.mirrorY === 1 ? ' activeButton' : '')}>
                                                    <BootstrapIcon type={45} />
                                                </div>
                                                <div id="mirrorX" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        mirrorX: prevState.mirrorX === 0 ? 1 : 0
                                                    }))
                                                }} className={"valueButton" + (values.mirrorX === 1 ? ' activeButton' : '')}>
                                                    <BootstrapIcon type={44} />
                                                </div>
                                            </div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeTransformContainer === 5 ? '' : ' display-none')}>
                                            <p>Image Settings</p>
                                            <div className="sliderCouple">

                                                <div className="imageTypeCoupleContainer">
                                                    <div className="imageTypeCouple">
                                                        <div id="quality-add" onClick={() => {
                                                            setImageQuality((prevState) => (
                                                                prevState < 0.9 ? prevState + 0.1 : 1
                                                            ))
                                                        }} className="valueButton">
                                                            +
                                                        </div>
                                                        <div id="quality-minmax" onClick={() => {
                                                            setImageQuality((prevState) => (
                                                                prevState < 1 ? 1 : 0.1
                                                            ))
                                                        }} className="imageTypeButton">
                                                            <p>{imageQuality < 1 ? 'MAX' : 'MIN'}</p>
                                                        </div>
                                                        <div id="quality-remove" onClick={() => {
                                                            setImageQuality((prevState) => (
                                                                prevState > 0.2 ? prevState - 0.1 : 0.1
                                                            ))
                                                        }} className="valueButton">
                                                            -
                                                        </div>
                                                    </div>

                                                    <p>Quality: {Number((imageQuality).toFixed(1))}</p>
                                                </div>
                                                <div className="imageTypeCoupleContainer">
                                                    <div className="imageTypeCouple">
                                                        <div id="imagePNG" onClick={() => { setIsPNG(true); }} className={"imageTypeButton" + (isPNG ? ' activeButton' : '')}>
                                                            PNG
                                                    </div>
                                                        <div id="imageJPG" onClick={() => { setIsPNG(false); }} className={"imageTypeButton" + (!isPNG ? ' activeButton' : '')}>
                                                            JPG
                                                    </div>
                                                    </div>

                                                    <p>Image Type</p>
                                                </div>
                                                <div className="imageTypeCoupleContainer">
                                                    <div className="imageTypeCouple">

                                                        <div id="imageOrigin" onClick={() => { setPostOriginal(true); }} className={"imageTypeButton" + (postOriginal ? ' activeButton' : '')}>
                                                            Original
                                                    </div>
                                                        <div id="imageEdit" onClick={() => { setPostOriginal(false); }} className={"imageTypeButton" + (!postOriginal ? ' activeButton' : '')}>
                                                            Edited
                                                    </div>
                                                    </div>

                                                    <p>Post Image</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="col-12 editorContaier">
                                        <div className="buttonRow border-bottom-5">
                                            <div id="toggle-original" onClick={() => { setActiveTransformContainer(activeTransformContainer === 0 ? -1 : 0) }} className={"editorButton" + (activeTransformContainer === 0 ? ' activeButton' : '')}><div className="editorButtonInfoTop infoLeft">Show Original</div><BootstrapIcon type={22} /></div>
                                            <div id="crop" onClick={() => { setActiveTransformContainer(activeTransformContainer === 1 ? -1 : 1) }} className={"editorButton" + (activeTransformContainer === 1 ? ' activeButton' : '')}><div className="editorButtonInfoTop">Crop</div><BootstrapIcon type={35} /></div>
                                            <div id="rotate" onClick={() => { setActiveTransformContainer(activeTransformContainer === 2 ? -1 : 2) }} className={"editorButton" + (activeTransformContainer === 2 ? ' activeButton' : '')}><div className="editorButtonInfoTop">Rotate</div><BootstrapIcon type={38} /></div>
                                            <div id="resize" onClick={() => { setActiveTransformContainer(activeTransformContainer === 3 ? -1 : 3) }} className={"editorButton" + (activeTransformContainer === 3 ? ' activeButton' : '')}><div className="editorButtonInfoTop">Resize</div><BootstrapIcon type={41} /></div>
                                            <div id="mirror" onClick={() => { setActiveTransformContainer(activeTransformContainer === 4 ? -1 : 4) }} className={"editorButton" + (activeTransformContainer === 4 ? ' activeButton' : '')}><div className="editorButtonInfoTop">Mirror</div><BootstrapIcon type={44} /></div>
                                            <div id="imageSettings" onClick={() => { setActiveTransformContainer(activeTransformContainer === 5 ? -1 : 5) }} className={"editorButton" + (activeTransformContainer === 5 ? ' activeButton' : '')}><div className="editorButtonInfoTop">Settings</div><BootstrapIcon type={51} /></div>
                                            <div id="render" className={"editorButton" + (!renderPaused ? ' activeButton' : '')} onClick={() => { setRenderPaused(!renderPaused) }}><div className="editorButtonInfoTop">{!renderPaused ? 'Render: ON' : 'Render: OFF'}</div><BootstrapIcon type={!renderPaused ? 56 : 57} /></div>
                                            <div id="download" className="editorButton" onClick={
                                                () => {
                                                    // Get ext
                                                    const fileExtension = fileName.slice(-4);

                                                    // Init new filename
                                                    let newFilename;

                                                    // Check image type
                                                    if (fileExtension === ".jpg" || fileExtension === ".png" || fileExtension === ".gif") {
                                                        // new filename
                                                        newFilename = fileName.substring(0, fileName.length - 4) + "-edited." + (isPNG ? 'png' : 'jpg');
                                                    }

                                                    // Call download
                                                    canvas = document.getElementById('canvas');
                                                    download(canvas, newFilename);
                                                }
                                            }><div className="editorButtonInfoTop">Download</div><BootstrapIcon type={54} /></div>
                                            <div id="reset" className="editorButton" onClick={() => { setPreviousPreset('initial'); setCurrentPreset(''); setCurrentCrop({ ...cropReset }); setValues({ ...resetValues }); setRenderPaused(false); setCommandStack([]); setRedoStack([]); }}><div className="editorButtonInfoTop infoRight">Reset</div><BootstrapIcon type={55} /></div>
                                        </div>
                                        <div id="canvasScreen" className={"originalImageContainer " + (expand ? (resizeClass + ' ' + resizeClassCropped) : '')}>
                                            <canvas data-caman-hidpi-disabled="true" id="presetCopy"></canvas>
                                            <img src={previewSource ? previewSource : ''} alt="selected file" className={"originalImage" + (activeTransformContainer === 0 ? '' : ' invisible')} />
                                            <canvas data-caman-hidpi-disabled="true" id="canvasCopy"></canvas>
                                            <ReactCrop id="reactCropID" className={(activeTransformContainer === 1) ? '' : 'invisible'} src={previewSource} crop={currentCrop} onChange={(crop, percentCrop) => { setCurrentCrop(percentCrop) }} onComplete={() => { cropCanvas(); addCropCommand(); }} />
                                            <canvas id="canvasCover" data-caman-hidpi-disabled="true" className={"blackCover " + ((activeTransformContainer !== 1) ? '' : 'invisible')}></canvas>
                                            <canvas id="canvas" data-caman-hidpi-disabled="true" className={((activeTransformContainer !== 0 && activeTransformContainer !== 1) ? '' : 'invisible')}></canvas>
                                        </div>
                                        <div className="buttonRow border-top-5">
                                            <div className={"editorButton" + (activeFilterContainer === 0 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 0 ? -1 : 0) }}><div className="editorButtonInfoBottom infoLeft">Preset Filter</div><BootstrapIcon type={50} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 1 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 1 ? -1 : 1) }}><div className="editorButtonInfoBottom">Light Level</div><BootstrapIcon type={37} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 2 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 2 ? -1 : 2) }}><div className="editorButtonInfoBottom">Colors</div><BootstrapIcon type={46} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 3 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 3 ? -1 : 3) }}><div className="editorButtonInfoBottom">RGB</div><BootstrapIcon type={47} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 4 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 4 ? -1 : 4) }}><div className="editorButtonInfoBottom">Colorize</div><BootstrapIcon type={48} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 5 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 5 ? -1 : 5) }}><div className="editorButtonInfoBottom">Noise</div><BootstrapIcon type={49} /></div>
                                            <div className={"editorButton" + (activeFilterContainer === 6 ? ' activeButton' : '')} onClick={() => { setActiveFilterContainer(activeFilterContainer === 6 ? -1 : 6) }}><div className="editorButtonInfoBottom">Vignette</div><BootstrapIcon type={72} /></div>
                                            <div className="editorButton" onClick={undoCommand}><BootstrapIcon type={52} /><div className="editorButtonInfoBottom">Undo</div></div>
                                            <div className="editorButton" onClick={redoCommand}><BootstrapIcon type={53} /><div className="editorButtonInfoBottom infoRight">Redo</div></div>
                                        </div>

                                    </div>
                                    <div className="activeFilterContainer">
                                        <div className="renderStatusContainer">
                                            {isRendering || isLoading ?
                                                <div className="lds-spinner-small"><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div><div></div></div>
                                                : null
                                            }
                                        </div>
                                        <div className={"buttonCoupleContainer presetContainer" + (activeFilterContainer === 0 ? '' : ' display-none')}>
                                            <div className={"presetButton " + ((values.presetFilter === '') ? 'activePreset' : '')} onClick={() => { setCurrentPreset('') }}>
                                                <img src={TEMPLATE} alt='preset' className="presetTemplate" />
                                                <p>None</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'vintage') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'vintage' ? '' : 'vintage') }}>
                                                <img src={VINTAGE} alt='preset' className="presetTemplate" />
                                                <p>Vintage</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'lomo') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'lomo' ? '' : 'lomo') }}>
                                                <img src={LOMO} alt='preset' className="presetTemplate" />
                                                <p>Lomo</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'thea') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'thea' ? '' : 'thea') }}>
                                                <img src={THEA} alt='preset' className="presetTemplate" />
                                                <p>Thea</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'clarity') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'clarity' ? '' : 'clarity') }}>
                                                <img src={CLARITY} alt='preset' className="presetTemplate" />
                                                <p>Clarity</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'sinCity') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'sinCity' ? '' : 'sinCity') }}>
                                                <img src={SINCITY} alt='preset' className="presetTemplate" />
                                                <p>Sin City</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'sunrise') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'sunrise' ? '' : 'sunrise') }}>
                                                <img src={SUNRISE} alt='preset' className="presetTemplate" />
                                                <p>Sunrise</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'crossProcess') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'crossProcess' ? '' : 'crossProcess') }}>
                                                <img src={CROSSPROCESS} alt='preset' className="presetTemplate" />
                                                <p>Process</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'orangePeel') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'orangePeel' ? '' : 'orangePeel') }}>
                                                <img src={ORANGEPEEL} alt='preset' className="presetTemplate" />
                                                <p>RedPeel</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'love') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'love' ? '' : 'love') }}>
                                                <img src={LOVE} alt='preset' className="presetTemplate" />
                                                <p>Love</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'grungy') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'grungy' ? '' : 'grungy') }}>
                                                <img src={GRUNGY} alt='preset' className="presetTemplate" />
                                                <p>Grungy</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'jarques') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'jarques' ? '' : 'jarques') }}>
                                                <img src={JARQUES} alt='preset' className="presetTemplate" />
                                                <p>Jarques</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'pinhole') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'pinhole' ? '' : 'pinhole') }}>
                                                <img src={PINHOLE} alt='preset' className="presetTemplate" />
                                                <p>Pinhole</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'oldBoot') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'oldBoot' ? '' : 'oldBoot') }}>
                                                <img src={OLDBOOT} alt='preset' className="presetTemplate" />
                                                <p>OldBoot</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'glowingSun') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'glowingSun' ? '' : 'glowingSun') }}>
                                                <img src={GLOWINGSUN} alt='preset' className="presetTemplate" />
                                                <p>Glow</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'hazyDays') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'hazyDays' ? '' : 'hazyDays') }}>
                                                <img src={HAZYDAYS} alt='preset' className="presetTemplate" />
                                                <p>HazyDays</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'herMajesty') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'herMajesty' ? '' : 'herMajesty') }}>
                                                <img src={HERMAJESTY} alt='preset' className="presetTemplate" />
                                                <p>Majestic</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'nostalgia') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'nostalgia' ? '' : 'nostalgia') }}>
                                                <img src={NOSTALGIA} alt='preset' className="presetTemplate" />
                                                <p>Nostalgia</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'hemingway') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'hemingway' ? '' : 'hemingway') }}>
                                                <img src={HEMINGWAY} alt='preset' className="presetTemplate" />
                                                <p>Bliss</p>
                                            </div>
                                            <div className={"presetButton " + ((values.presetFilter === 'concentrate') ? 'activePreset' : '')} onClick={() => { setCurrentPreset(currentPreset === 'concentrate' ? '' : 'concentrate') }}>
                                                <img src={CONCENTRATE} alt='preset' className="presetTemplate" />
                                                <p>Focus</p>
                                            </div>
                                        </div>

                                        <div className={"buttonCoupleContainer" + (activeFilterContainer === 1 ? '' : ' display-none')}>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={23} />
                                                <div id="brightness-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        brightness: (prevState.brightness < 95) ? (prevState.brightness + 5) : 100
                                                    }));
                                                }}>+</div>
                                                <div id="brightness-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        brightness: (prevState.brightness > -95) ? (prevState.brightness - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={24} />
                                                <div id="contrast-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        contrast: (prevState.contrast < 95) ? (prevState.contrast + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="contrast-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        contrast: (prevState.contrast > -95) ? (prevState.contrast - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={25} />
                                                <div id="exposure-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        exposure: (prevState.exposure < 95) ? (prevState.exposure + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="exposure-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        exposure: (prevState.exposure > -95) ? (prevState.exposure - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={36} />
                                                <div id="gamma-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        gamma: (prevState.gamma < 4.9) ? (parseFloat((prevState.gamma + 0.1).toFixed(1))) : 5
                                                    }))
                                                }}>+</div>
                                                <div id="gamma-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        gamma: (prevState.gamma > 0.1) ? (parseFloat((prevState.gamma - 0.1).toFixed(1))) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={73} />
                                                <div id="opacity-add" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        opacity: prevState.opacity < 0.95 ? (parseFloat((prevState.opacity + 0.05).toFixed(2))) : 1
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <div id="opacity-remove" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        opacity: prevState.opacity > 0.05 ? (parseFloat((prevState.opacity - 0.05).toFixed(2))) : 0
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>
                                            </div>

                                        </div>

                                        <div className={"buttonCoupleContainer" + (activeFilterContainer === 2 ? '' : ' display-none')}>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={26} />
                                                <div id="saturation-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        saturation: (prevState.saturation < 95) ? (prevState.saturation + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="saturation-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        saturation: (prevState.saturation > -95) ? (prevState.saturation - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={27} />
                                                <div id="vibrance-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vibrance: (prevState.vibrance < 95) ? (prevState.vibrance + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="vibrance-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vibrance: (prevState.vibrance > -95) ? (prevState.vibrance - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={34} />
                                                <div id="hue-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        hue: (prevState.hue < 95) ? (prevState.hue + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="hue-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        hue: (prevState.hue > 5) ? (prevState.hue - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={59} />
                                                <div id="invert-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        invert: true
                                                    }))
                                                }}><BootstrapIcon type={30} /></div>
                                                <div id="invert-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        invert: false
                                                    }))
                                                }}><BootstrapIcon type={31} /></div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={60} />
                                                <div id="sepia-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        sepia: (prevState.sepia < 95) ? (prevState.sepia + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="sepia-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        sepia: (prevState.sepia > 5) ? (prevState.sepia - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={33} />
                                                <div id="clip-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        clip: (prevState.clip < 95) ? (prevState.clip + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="clip-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        clip: (prevState.clip > 5) ? (prevState.clip - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                        </div>

                                        <div className={"buttonCoupleContainer" + (activeFilterContainer === 3 ? '' : ' display-none')}>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={29} fill='red' />
                                                <div id="channelR-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelR: (prevState.channelR < 95) ? (prevState.channelR + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="channelR-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelR: (prevState.channelR > -95) ? (prevState.channelR - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={29} fill='green' />
                                                <div id="channelG-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelG: (prevState.channelG < 95) ? (prevState.channelG + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="channelG-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelG: (prevState.channelG > -95) ? (prevState.channelG - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={29} fill='blue' />
                                                <div id="channelB-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelB: (prevState.channelB < 95) ? (prevState.channelB + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="channelB-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        channelB: (prevState.channelB > -95) ? (prevState.channelB - 5) : -100
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={29} fill='grey' />
                                                <div id="greyscale-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        greyscale: true
                                                    }))
                                                }}><BootstrapIcon type={30} /></div>
                                                <div id="greyscale-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        greyscale: false
                                                    }))
                                                }}><BootstrapIcon type={31} /></div>
                                            </div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeFilterContainer === 4 ? '' : ' display-none')}>
                                            <div className="sliderCouple">
                                                <div className="sliderFlexWrap">
                                                    <SliderPicker color={currentColor} onChange={(color) => { setCurrentColor(color.hex) }} onChangeComplete={(color) => { setEndColor(color.hex) }} />
                                                </div>
                                                <div id="colorizeStrength-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        colorizeStrength: (prevState.colorizeStrength < 95) ? (prevState.colorizeStrength + 5) : 100
                                                    }))
                                                }}>+</div>
                                                <div id="colorizeStrength-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        colorizeStrength: (prevState.colorizeStrength > 5) ? (prevState.colorizeStrength - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                        </div>

                                        <div className={"buttonCoupleContainer" + (activeFilterContainer === 5 ? '' : ' display-none')}>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={61} />
                                                <div id="noise-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        noise: (prevState.noise < 75) ? (prevState.noise + 5) : 80
                                                    }))
                                                }}>+</div>
                                                <div id="noise-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        noise: (prevState.noise > 5) ? (prevState.noise - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={68} />
                                                <div id="sharpen-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        sharpen: (prevState.sharpen < 115) ? (prevState.sharpen + 5) : 120
                                                    }))
                                                }}>+</div>
                                                <div id="sharpen-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        sharpen: (prevState.sharpen > 5) ? (prevState.sharpen - 5) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={32} />
                                                <div id="stackBlur-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        stackBlur: (prevState.stackBlur < 19) ? (prevState.stackBlur + 1) : 20
                                                    }))
                                                }}>+</div>
                                                <div id="stackBlur-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        stackBlur: (prevState.stackBlur > 1) ? (prevState.stackBlur - 1) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <BootstrapIcon type={58} />
                                                <div id="radialBlur-add" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        radialBlur: (prevState.radialBlur < 7) ? (prevState.radialBlur + 1) : 8
                                                    }))
                                                }}>+</div>
                                                <div id="radialBlur-remove" className="valueButton" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        radialBlur: (prevState.radialBlur > 1) ? (prevState.radialBlur - 1) : 0
                                                    }))
                                                }}>-</div>
                                            </div>
                                            <div className="buttonCouple">
                                                <div className="buttonCouple">
                                                    <BootstrapIcon type={67} />
                                                    <div id="dither-add" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            dither: true
                                                        }))
                                                    }}><BootstrapIcon type={30} /></div>
                                                    <div id="dither-remove" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            dither: false
                                                        }))
                                                    }}><BootstrapIcon type={31} /></div>
                                                </div>
                                                <div className="buttonCouple">
                                                    <BootstrapIcon type={69} text={
                                                        values.ditherAlgo === 1 ? 'j' :
                                                            values.ditherAlgo === 2 ? 'S' :
                                                                values.ditherAlgo === 3 ? 'a' :
                                                                    values.ditherAlgo === 4 ? 'b' :
                                                                        values.ditherAlgo === 5 ? 'si' :
                                                                            values.ditherAlgo === 6 ? 's2' :
                                                                                values.ditherAlgo === 7 ? 'sl' :
                                                                                    'f'} />
                                                    <div id="ditherAlgo-add" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            ditherAlgo: prevState.ditherAlgo < 7 ? prevState.ditherAlgo + 1 : 0
                                                        }))
                                                    }}><BootstrapIcon type={70} /></div>
                                                    <div id="ditherAlgo-remove" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            ditherAlgo: prevState.ditherAlgo > 0 ? prevState.ditherAlgo - 1 : 7
                                                        }))
                                                    }}><BootstrapIcon type={71} /></div>
                                                </div>
                                            </div>
                                            <div className="buttonCouple">
                                                <div className="buttonCouple">
                                                    <BootstrapIcon type={62} />
                                                    <div id="motionBlurLayers-add" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            motionBlurLayers: (prevState.motionBlurLayers < 5) ? (prevState.motionBlurLayers + 1) : 6
                                                        }))
                                                    }}>+</div>
                                                    <div id="motionBlurLayers-remove" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            motionBlurLayers: (prevState.motionBlurLayers > 1) ? (prevState.motionBlurLayers - 1) : 0
                                                        }))
                                                    }}>-</div>
                                                </div>
                                                <div className="buttonCouple">
                                                    <BootstrapIcon type={
                                                        (values.motionBlurAngle === 45 || values.motionBlurAngle === 225) ? 64 :
                                                            (values.motionBlurAngle === 90 || values.motionBlurAngle === 270) ? 63 :
                                                                (values.motionBlurAngle === 135 || values.motionBlurAngle === 315) ? 66 :
                                                                    65} />
                                                    <div id="motionBlurAngle-add" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            motionBlurAngle: ((prevState.motionBlurAngle % 45) !== 0) ? 0 : (prevState.motionBlurAngle + 45) % 360
                                                        }))
                                                    }}><BootstrapIcon type={70} /></div>
                                                    <div id="motionBlurAngle-remove" className="valueButton" onClick={() => {
                                                        setValues((prevState) => ({
                                                            ...prevState,
                                                            motionBlurAngle: ((prevState.motionBlurAngle % 45) !== 0) ? 0 : (prevState.motionBlurAngle - 45 + (prevState.motionBlurAngle < 45 ? 360 : 0)) % 360
                                                        }))
                                                    }}><BootstrapIcon type={71} /></div>
                                                </div>
                                            </div>
                                        </div>

                                        <div className={"sliderCoupleContainer" + (activeFilterContainer === 6 ? '' : ' display-none')}>
                                            <div className="sliderCouple">
                                                <div id="vignetteSize-add" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vignetteSize: prevState.vignetteSize < 99 ? prevState.vignetteSize + 1 : 100
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <p>V Size</p>
                                                <div id="vignetteSize-remove" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vignetteSize: prevState.vignetteSize > 1 ? prevState.vignetteSize - 1 : 0
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>
                                                <div className="sliderFlexWrap Aspect">

                                                    <RangeSlider
                                                        value={currentVignetteSize}
                                                        onChange={(e) => { setCurrentVignetteSize(e.target.value) }}
                                                        onAfterChange={
                                                            (e) => {
                                                                setValues((prevState) => ({
                                                                    ...prevState,
                                                                    vignetteSize: parseInt(e.target.value)
                                                                }))
                                                            }
                                                        }
                                                        min={0}
                                                        max={100}
                                                        step={1}
                                                        className="resizeRange"
                                                        variant="light"
                                                        tooltipLabel={currentValue => `${currentValue}%`}
                                                        tooltipPlacement='top'
                                                        tooltip='auto'
                                                    />
                                                </div>

                                                <div className="sliderFlexWrap Aspect">

                                                    <RangeSlider
                                                        value={currentVignetteStrength}
                                                        onChange={(e) => { setCurrentVignetteStrength(e.target.value) }}
                                                        onAfterChange={
                                                            (e) => {
                                                                setValues((prevState) => ({
                                                                    ...prevState,
                                                                    vignetteStrength: parseInt(e.target.value)
                                                                }))
                                                            }
                                                        }
                                                        min={0}
                                                        max={100}
                                                        step={1}
                                                        className="resizeRange"
                                                        variant="light"
                                                        tooltipLabel={currentValue => `${currentValue}%`}
                                                        tooltipPlacement='bottom'
                                                        tooltip='auto'
                                                    />
                                                </div>
                                                <div id="vignetteStrength-add" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vignetteStrength: prevState.vignetteStrength < 99 ? prevState.vignetteStrength + 1 : 100
                                                    }))
                                                }} className="valueButton">
                                                    +
                                                </div>
                                                <p>Effect</p>
                                                <div id="vignetteStrength-remove" onClick={() => {
                                                    setValues((prevState) => ({
                                                        ...prevState,
                                                        vignetteStrength: prevState.vignetteStrength > 1 ? prevState.vignetteStrength - 1 : 0
                                                    }))
                                                }} className="valueButton">
                                                    -
                                                    </div>

                                            </div>
                                        </div>
                                    </div>


                                </div>

                                <hr className="round" />
                                <div className={userVerified ? 'display-none' : 'unverifiedEditor'}>
                                    <p className="unverified-text">You must be a verified user in order to post your images.</p>
                                    <NavLink to="/login" className="unverified-text">Login</NavLink>
                                </div>
                                <div className={userVerified ? '' : 'display-none'}>
                                    <Form.Group controlId="newPostDescription">
                                        <Form.Label>Description</Form.Label>
                                        <Form.Control autoComplete="off" as="textarea" rows={5} onChange={(e) => { setDescription(checkText(e.target.value)); document.getElementById('newPostDescription').value = checkText(e.target.value); }} />
                                    </Form.Group>
                                    <Form.Group className="postButtonHolder">
                                        <button type="submit" onClick={postFile} name="button" className="genericButton">Post</button>
                                    </Form.Group>
                                    <DropdownButton className="changePostView" title={postView}>
                                        <Dropdown.Item onSelect={() => { setPostView('Public') }}>Public</Dropdown.Item>
                                        <Dropdown.Item onSelect={() => { setPostView('Friends') }} >Friends</Dropdown.Item>
                                        <Dropdown.Item onSelect={() => { setPostView('Private') }} >Private</Dropdown.Item>
                                    </DropdownButton>
                                </div>
                            </Form>
                            <hr className="round" />
                        </div>




                        <div className="blog-post">
                            <h5 className="w">Link Vizije</h5>
                            <p className="blog-post-meta">Zadnje ažurirano 8. studenog 2020. <strong> <a className="alink" href="https://docs.google.com/document/d/141DHijMdyPfeffnDDo_hYwJRKfGQT5NC6UDfMsEDl3Y/edit?usp=sharing" target="_blank" rel="noreferrer">Vizija</a> </strong></p>
                            <a href="https://github.com/MarkoRezic/RTFotoEditor" target="_blank" rel="noreferrer">
                                <span className="githubContainer">
                                    <img alt='' src={GITHUB} className="github" />
                                    <img alt='' src={GITHUBLOGO} className="githubLogo" />
                                </span>
                            </a>
                            <a href="http://camanjs.com/" target="_blank" rel="noreferrer">
                                <span className="githubContainer">
                                    <img alt='' src={CAMANJS} className="github" />
                                    <img alt='' src={CAMERA} className="githubLogo" />
                                </span>
                            </a>
                        </div>



                    </div>
                </div>
            </div>
        </div >
    );
}

export default Editor;