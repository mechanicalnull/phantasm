// seeds = [seed_object, ... ]; written in by the Python code above this
// Globals
var play_on = false;
var do_loop = false;
var do_highlight_cur = false;
var frame_interval = 1000;
var play_callback;

var svg_obj;
var play_button;
var loop_button;
var prev_button;
var next_button;
var slider_obj;
var highlight_cur_button;
var cur_frame_span;
var max_frame_span;
var cur_seed_span;
var panZoomGraph;

var num_colors = 3; // numbers of colors in gradient, including new and old
var new_color = [255, 0, 0]; // newest blocks color
var old_color = [0, 0, 255]; // old blocks color
var cur_seed_color = [195, 155, 0]; // replaces new_color if highlighting current seed
// golden: [195, 155, 0] // replaces new_color if highlighting current seed
// dark cyan: [0, 139, 139]
// sea foam: [60, 179, 113]
var colors;


// global init function once page is loaded
function init_anim() {
    //console.log("init_anim");

    // initialize page element handles
    svg_obj = document.getElementById('anim_graph');
    play_button = document.getElementById('play_button');
    loop_button = document.getElementById('loop_button');
    prev_button = document.getElementById('prev_button');
    next_button = document.getElementById('next_button');
    slider_obj = document.getElementById('slider');
    highlight_cur_button = document.getElementById('highlight_cur_button');
    cur_frame_span = document.getElementById('cur_frame_span');
    max_frame_span = document.getElementById('max_frame_span');
    cur_seed_span = document.getElementById('cur_seed_span');
    scalable_svg = document.getElementById('functiongraph')[0];

    // Helpers to implement click'n'drag to pan for the SVG
    var panZoomGraph = svgPanZoom('#anim_graph', {
        minZoom: 0.25,
        maxZoom: 8,
        beforePan: limit_pan,
    });

    // set up the slider and text values
    slider_obj.max = seeds.length - 1;
    slider_obj.min = 0;
    slider_obj.value = 0;
    cur_frame_span.innerHTML = 0;
    max_frame_span.innerHTML = seeds.length - 1;
    // 'change' and 'input' are different, 'input' is responsive
    slider_obj.addEventListener('input', handle_slider_change);

    // mix colors once
    colors = mix_colors(new_color, old_color, num_colors)

    // set button click handlers
    play_button.addEventListener('click', toggle_play);
    loop_button.addEventListener('click', toggle_loop);
    prev_button.addEventListener('click', click_prev);
    next_button.addEventListener('click', click_next);
    highlight_cur_button.addEventListener('click', click_highlight_cur);

    // show initial highlights and kick off the animation
    reset_anim();
    toggle_play();
}


// SVG pan and zoom using https://github.com/ariutta/svg-pan-zoom

// limit_pan based on the demo in that repo
function limit_pan(oldPan, newPan) {
    let sizes = this.getSizes();

    let gutterWidth = sizes.viewBox.width / 3;
    let gutterHeight = sizes.viewBox.height / 3;

    let leftLimit = -((sizes.viewBox.x + sizes.viewBox.width) * sizes.realZoom) + gutterWidth;
    let rightLimit = sizes.width - gutterWidth - (sizes.viewBox.x * sizes.realZoom);
    let topLimit = -((sizes.viewBox.y + sizes.viewBox.height) * sizes.realZoom) + gutterHeight;
    let bottomLimit = sizes.height - gutterHeight - (sizes.viewBox.y * sizes.realZoom);

    customPan = {};
    customPan.x = Math.max(leftLimit, Math.min(rightLimit, newPan.x));
    customPan.y = Math.max(topLimit, Math.min(bottomLimit, newPan.y));

    return customPan;
}


// Functions to handle interaction with controls

function toggle_play() {
    //console.log(play_on);

    // regardless of start or stop we should cancel any previous callback
    if (play_callback) {
        clearTimeout(play_callback);
        play_callback = undefined;
    }

    play_on = !play_on;
    if (play_on) {
        play_button.style.background = "lightgreen";
        play_callback = setTimeout(play_animation, frame_interval);
    } else {
        play_button.style.background = "";
    }
}

function toggle_loop() {
    //console.log(do_loop);

    do_loop = !do_loop;
    if (do_loop)
        loop_button.style.background = "lightgreen";
    else
        loop_button.style.background = "";
}

function click_prev() {
    if (play_on)
        toggle_play();

    let new_index = frame_index - 1;
    // allow prev to loop back around
    if (new_index == 0 && do_loop)
        new_index = seeds.length;

    if (new_index > 0)
        run_anim_up_to(new_index);
}

function click_next() {
    if (play_on)
        toggle_play();

    advance_animation();
}

function handle_slider_change() {
    let cur_value = parseInt(slider_obj.value, 10);
    //console.log(`handle_slider_change: ${cur_value}`)

    run_anim_up_to(cur_value + 1);

    if (play_on)
        toggle_play();
}

function click_highlight_cur() {
    if (play_on) {
        toggle_play();
    }

    do_highlight_cur = !do_highlight_cur;
    if (do_highlight_cur) {
        highlight_cur_button.style.background = "lightgreen";
    } else {
        highlight_cur_button.style.background = "";
    }

    // apply the new coloring
    run_anim_up_to(frame_index);
}


// animation functions

// animation callback trigger
function play_animation() {
    if (play_on) {
        //console.log(`play_animation ${Date()}`)
        advance_animation();
    }
    // advance_animation can cancel play_on
    if (play_on) {
        play_callback = setTimeout(play_animation, frame_interval);
    }
}

var frame_index = 0;
function reset_anim() {
    frame_index = 0;
    reset_all_blocks();
    advance_animation();
}

function advance_animation() {
    //console.log(`advance_animation: ${frame_index}`);
    // check if trying to advance past last frame
    if (frame_index >= seeds.length) {
        if (do_loop) {
            reset_anim();
        } else {
            if (play_on)
                toggle_play();
        }
        return;
    }

    slider_obj.value = frame_index;
    cur_frame_span.innerHTML = frame_index;
    cur_seed_span.innerHTML = `Time: ${seeds[frame_index].time}, Name: ${seeds[frame_index].name}`;
    highlight_last_n(frame_index);
    //highlight_index(frame_index);

    frame_index += 1;
}

// up to, meaning "index" is technically one more than is shown
function run_anim_up_to(index) {
    if ((index < 0) || (index > seeds.length)) {
        return;
    }
    // FUTURE: implement better strategy here for large datasets
    //console.log(`running to ${index}`);
    reset_anim();
    while (frame_index < index) {
        advance_animation();
    }
}

// Highlight/Color functions

function highlight_index(index) {
    // basic highlight, just one color
    let cur_seed = seeds[frame_index];
    //console.log(cur_seed);


    for (block of cur_seed.blocks) {
        //console.log(block);
        highlight_block(block);
    }

}

function highlight_last_n(index) {
    // colors already initialized in init function

    for (let i = num_colors - 1; i >= 0; i--) {
        let cur_index = index - i;
        if (cur_index < 0)
            continue;

        let seed = seeds[cur_index];
        let color = colors[i];
        //console.log(`${i} ${seed} ${color}`);

        // handle highlight current seed, override new_color
        if (do_highlight_cur && color == new_color) {
            for (block of seed.blocks) {
                set_block_color(block, cur_seed_color);
            }
        }
        // otherwise normal colors
        else {
            for (block of seed.blocks) {
                //console.log(block);
                set_block_color(block, color);
            }
        }
    }

    if (do_highlight_cur) {
        for (block of seeds[frame_index].extras) {
            set_block_color(block, cur_seed_color);
        }
    }
}

// currently linear interpolation of RGB colors
function mix_colors(start, end, steps) {
    if (steps == 1) return [start];
    if (steps == 2) return [start, end];

    let num_intermediates = steps - 2;

    let rgb_deltas = [
        end[0] - start[0],
        end[1] - start[1],
        end[2] - start[2]
    ];
    let rgb_increments = [
        rgb_deltas[0] / (num_intermediates + 1),
        rgb_deltas[1] / (num_intermediates + 1),
        rgb_deltas[2] / (num_intermediates + 1)
    ]

    let color_steps = [];
    color_steps.push(start);
    for (let i = 1; i < (num_intermediates+1); i++) {
        cur_color = [
            start[0] + rgb_increments[0] * i,
            start[1] + rgb_increments[1] * i,
            start[2] + rgb_increments[2] * i
        ];
        color_steps.push(cur_color);
    }
    color_steps.push(end);

    return color_steps;
}

// Element color manipulation functions
function set_block_color(block_id, rgb) {
    let block = svg_obj.getElementById(block_id);
    block.style.fill = `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]})`;
}

function highlight_block(block_id) {
    set_block_color(block_id, [255, 0, 0]);
}

function reset_block_color(block_id) {
    let block = svg_obj.getElementById(block_id);
    block.style.fill = ''; // default CSS rule takes over
}

function reset_all_blocks() {
    let all_blocks = svg_obj.querySelectorAll(".basicblock");

    for (const block of all_blocks) {
        reset_block_color(block.id);
    }
}
