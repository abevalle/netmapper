function createGraph(data) {
    const width = window.innerWidth;
    const height = window.innerHeight;
    
    // Clear previous graph
    d3.select("#graph").selectAll("*").remove();
    
    const svg = d3.select("#graph")
        .append("svg")
        .attr("width", width)
        .attr("height", height);
        
    const graphGroup = svg.append("g")
        .attr("class", "graph-container");
    
    // Create links
    const link = graphGroup.selectAll(".link")
        .data(data.links)
        .join("line")
        .attr("class", "link");
    
    // Create nodes
    const node = graphGroup.selectAll(".node")
        .data(data.nodes)
        .join("g")
        .attr("class", "node");
    
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-1000))
        .force("x", d3.forceX(0))
        .force("y", d3.forceY(0))
        .force("center", d3.forceCenter(0, 0));
    
    // Wait for simulation to settle
    for (let i = 0; i < 50; ++i) simulation.tick();
    
    // Calculate initial zoom transform
    const bounds = graphGroup.node().getBBox();
    const padding = 50;
    const fullWidth = bounds.width + padding * 2;
    const fullHeight = bounds.height + padding * 2;
    const scale = 0.95 * Math.min(
        width / fullWidth,
        height / fullHeight
    );

    // Center with the scale
    const tx = width/2 - bounds.x * scale - bounds.width * scale/2;
    const ty = height/2 - bounds.y * scale - bounds.height * scale/2;

    // Set up zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => {
            graphGroup.attr("transform", event.transform);
        });

    // Apply initial transform with transition
    svg.call(zoom)
       .transition()
       .duration(750)
       .call(zoom.transform, 
            d3.zoomIdentity
                .translate(tx, ty)
                .scale(scale)
        );

    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
            
        node
            .attr("transform", d => `translate(${d.x},${d.y})`);
    });
}