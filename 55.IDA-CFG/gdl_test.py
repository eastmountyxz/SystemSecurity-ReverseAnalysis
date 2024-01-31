from easygraph.datasets import get_graph_karateclub
import easygraph as eg
G = get_graph_karateclub()
# Calculate five shs(Structural Hole Spanners) in G
shs = eg.common_greedy(G, 5)
# Draw the Graph, and the shs is marked by red star
eg.draw_SHS_center(G, shs)
# Draw CDF curves of "Number of Followers" of SH spanners and ordinary users in G.
eg.plot_Followers(G, shs)
